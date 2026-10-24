//! Named-key rows: create, block/unblock, public-key derivation, and the
//! state-checked unwrap used by the decrypt release guard.
//!
//! A key's kind follows from its path: a path under `apps/` is a deletable
//! key (derived from the network secret, the path and a per-key random seed),
//! every other path is a deterministic key (no seed). The create, block and
//! unblock writes all run under the network row lock.

use sea_orm::{
    sea_query::Expr, ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait,
    DatabaseTransaction, DbBackend, DbErr, EntityTrait, PaginatorTrait, QueryFilter, QuerySelect,
};

use crate::db::begin_write_transaction;
use crate::models::{encryption_network, encryption_network_key};

use super::backend::{KeyBackendError, KeySeed};
use super::key_id::{app_id_of, is_apps_path, EncryptionResource, KeyKind, KeyLocation};
use super::network_id::NetworkId;
use super::service::{is_unique_violation, now_rfc3339, EncryptionService, EncryptionServiceError};
use super::types::{NetworkState, ALG_X25519_AES256GCM};

/// Interim hard cap per network. Counts every key row per network, deleted
/// rows included. Placeholder value pending the node-config owner.
pub const DEFAULT_KEY_CAP_PER_NETWORK: u64 = 1000;
/// Interim hard cap per `apps/<app id>/` prefix. Counts every key row under
/// the prefix, deleted rows included, until a deleted row is reused.
pub const DEFAULT_KEY_CAP_PER_APP_PREFIX: u64 = 100;
const KEY_VERSION_INITIAL: i64 = 1;

/// Key row state. Any stored state other than `active`, `blocked` or `deleted`
/// is refused as a corrupt row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Active,
    Blocked,
    Deleted,
}

impl KeyState {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyState::Active => "active",
            KeyState::Blocked => "blocked",
            KeyState::Deleted => "deleted",
        }
    }

    fn parse(stored: &str) -> Result<Self, EncryptionServiceError> {
        match stored {
            "active" => Ok(KeyState::Active),
            "blocked" => Ok(KeyState::Blocked),
            "deleted" => Ok(KeyState::Deleted),
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

/// A stored key row whose kind, state and seed are consistent with its path.
struct CheckedRow {
    row: encryption_network_key::Model,
    kind: KeyKind,
    state: KeyState,
}

/// Refuses a row that is not readable as a key: an unknown state or kind, a
/// kind the path does not imply, or a deletable row that has not been deleted
/// and holds no seed.
fn check_row(row: encryption_network_key::Model) -> Result<CheckedRow, EncryptionServiceError> {
    let state = KeyState::parse(&row.state)?;
    let kind = KeyKind::parse(&row.kind).ok_or(EncryptionServiceError::CorruptKeyRow)?;
    if kind != KeyKind::for_path(&row.key_path) {
        return Err(EncryptionServiceError::CorruptKeyRow);
    }
    if kind == KeyKind::Deletable && state != KeyState::Deleted && row.sealed_seed.is_none() {
        return Err(EncryptionServiceError::CorruptKeyRow);
    }
    Ok(CheckedRow { row, kind, state })
}

fn descriptor(row: encryption_network_key::Model) -> Result<KeyDescriptor, EncryptionServiceError> {
    let CheckedRow { row, state, .. } = check_row(row)?;
    Ok(KeyDescriptor {
        network_id: row.network_id,
        key_path: row.key_path,
        alg: ALG_X25519_AES256GCM.to_string(),
        key_version: row.key_version,
        public_encryption_key: row.public_key,
        kind: row.kind,
        state,
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
/// for an ACTIVE deterministic key, `key_deleted` for a deleted row (the
/// deletable case never reaches here: it is reinstalled), otherwise
/// `key_exists`.
fn existing_create_answer(
    row: encryption_network_key::Model,
) -> Result<KeyDescriptor, EncryptionServiceError> {
    let CheckedRow { row, kind, state } = check_row(row)?;
    match state {
        KeyState::Deleted => Err(EncryptionServiceError::KeyDeleted),
        KeyState::Active if kind == KeyKind::Deterministic => descriptor(row),
        _ => Err(EncryptionServiceError::KeyExists),
    }
}

/// Takes the row lock that serializes the key writes of one network on
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

/// The unsealed network secret with, for a deletable key, a new seed and its
/// sealed form.
type NetworkSecretAndSeed = (x25519_dalek::StaticSecret, Option<KeySeed>, Option<Vec<u8>>);

/// What `key.create` found or did inside its transaction.
enum CreateStep {
    Inserted(encryption_network_key::Model),
    /// A deleted deletable row was reused with a fresh seed.
    Reinstalled(encryption_network_key::Model),
    Existing(encryption_network_key::Model),
    /// The insert lost a unique-key race to another writer.
    Raced,
}

impl EncryptionService {
    /// `key.create`. `deletable` must equal what the path implies (true under
    /// `apps/`, false elsewhere). Idempotent for an identical ACTIVE
    /// deterministic key (returns the existing descriptor). A `deleted`
    /// deletable row is reused with a fresh seed, state `active` and the next
    /// key version; any other existing row is `key_exists`, and a deleted
    /// deterministic row is `key_deleted`. The existence check and the write
    /// share one transaction taken under the network row lock.
    pub async fn create_key(
        &self,
        loc: &KeyLocation,
        deletable: bool,
    ) -> Result<KeyDescriptor, EncryptionServiceError> {
        if deletable != (loc.kind() == KeyKind::Deletable) {
            return Err(EncryptionServiceError::KeyPathInvalid(
                "deletable must be true for key paths under apps/ and false elsewhere".to_string(),
            ));
        }
        let _writer = match &self.sqlite_writer_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        let network = network_of(loc)?;
        let tx = begin_write_transaction(&self.db, None).await?;
        // Every outcome ends the transaction here. A dropped transaction is
        // rolled back by a task sqlx spawns, and the network row lock would
        // outlive this call until that task runs.
        match self.create_key_in(&tx, &network, loc).await {
            Ok(CreateStep::Inserted(row) | CreateStep::Reinstalled(row)) => {
                tx.commit().await?;
                descriptor(row)
            }
            Ok(CreateStep::Existing(row)) => {
                tx.rollback().await?;
                existing_create_answer(row)
            }
            Ok(CreateStep::Raced) => {
                // Another writer committed the same key first. Roll back, then
                // answer from the committed row on the pool.
                tx.rollback().await?;
                match find_key_row(&self.db, &network, loc.path()).await? {
                    Some(existing) => existing_create_answer(existing),
                    None => Err(EncryptionServiceError::KeyExists),
                }
            }
            Err(err) => {
                // The original error is the answer. A rollback that fails has
                // lost the connection, which ends the transaction anyway.
                let _ = tx.rollback().await;
                Err(err)
            }
        }
    }

    async fn create_key_in(
        &self,
        tx: &DatabaseTransaction,
        network: &NetworkId,
        loc: &KeyLocation,
    ) -> Result<CreateStep, EncryptionServiceError> {
        lock_network_row(tx, network).await?;
        let net = load_active_network(tx, network).await?;
        let kind = loc.kind();

        if let Some(row) = find_key_row(tx, network, loc.path()).await? {
            let checked = check_row(row)?;
            if checked.state == KeyState::Deleted && checked.kind == KeyKind::Deletable {
                return self.reinstall_key_in(tx, &net, loc, checked.row).await;
            }
            return Ok(CreateStep::Existing(checked.row));
        }

        self.check_key_caps(tx, network, loc).await?;

        let (network_secret, seed, sealed_seed) = self.open_secret_and_new_seed(&net, kind)?;
        let public = self.backend.derive_named_public_key(
            &network_secret,
            &canonical_key_urn(loc),
            seed.as_ref(),
        )?;

        let now = now_rfc3339();
        let inserted = encryption_network_key::ActiveModel {
            network_id: Set(network.to_string()),
            key_path: Set(loc.path().to_string()),
            kind: Set(kind.as_str().to_string()),
            state: Set(KeyState::Active.as_str().to_string()),
            public_key: Set(public),
            sealed_seed: Set(sealed_seed),
            key_version: Set(KEY_VERSION_INITIAL),
            created_at: Set(now.clone()),
            updated_at: Set(now),
        }
        .insert(tx)
        .await;
        match inserted {
            Ok(row) => Ok(CreateStep::Inserted(row)),
            Err(err) if is_unique_violation(&err) => Ok(CreateStep::Raced),
            Err(err) => Err(err.into()),
        }
    }

    /// Unseals the network secret and, for a deletable key, makes a fresh
    /// seed. Returns the sealed seed to store.
    fn open_secret_and_new_seed(
        &self,
        net: &encryption_network::Model,
        kind: KeyKind,
    ) -> Result<NetworkSecretAndSeed, EncryptionServiceError> {
        let sealed = net
            .sealed_private_key
            .as_deref()
            .ok_or(KeyBackendError::SealedKeyMissing)?;
        let network_secret = self.backend.open_network_secret(sealed)?;
        match kind {
            KeyKind::Deterministic => Ok((network_secret, None, None)),
            KeyKind::Deletable => {
                let (seed, sealed_seed) = self.backend.generate_seed()?;
                Ok((network_secret, Some(seed), Some(sealed_seed)))
            }
        }
    }

    /// The per-network and per-app-prefix caps for a new row.
    async fn check_key_caps(
        &self,
        tx: &DatabaseTransaction,
        network: &NetworkId,
        loc: &KeyLocation,
    ) -> Result<(), EncryptionServiceError> {
        let count = encryption_network_key::Entity::find()
            .filter(encryption_network_key::Column::NetworkId.eq(network.to_string()))
            .count(tx)
            .await?;
        if count >= self.key_cap_per_network {
            return Err(EncryptionServiceError::KeyLimitExceeded);
        }
        if let Some(app_id) = app_id_of(loc.path()) {
            let prefix = format!("apps/{app_id}/");
            // Compared as bytes here, never with a LIKE pattern or a range.
            let paths: Vec<String> = encryption_network_key::Entity::find()
                .select_only()
                .column(encryption_network_key::Column::KeyPath)
                .filter(encryption_network_key::Column::NetworkId.eq(network.to_string()))
                .into_tuple()
                .all(tx)
                .await?;
            let under_prefix = paths.iter().filter(|p| p.starts_with(&prefix)).count() as u64;
            if under_prefix >= self.key_cap_per_app_prefix {
                return Err(EncryptionServiceError::KeyLimitExceeded);
            }
        }
        Ok(())
    }

    /// Reuses a `deleted` deletable row: fresh seed, state `active`, key
    /// version + 1. The row is updated only while it is still `deleted` at
    /// the version read.
    async fn reinstall_key_in(
        &self,
        tx: &DatabaseTransaction,
        net: &encryption_network::Model,
        loc: &KeyLocation,
        row: encryption_network_key::Model,
    ) -> Result<CreateStep, EncryptionServiceError> {
        let (network_secret, seed, sealed_seed) =
            self.open_secret_and_new_seed(net, KeyKind::Deletable)?;
        let public = self.backend.derive_named_public_key(
            &network_secret,
            &canonical_key_urn(loc),
            seed.as_ref(),
        )?;
        let updated = encryption_network_key::Entity::update_many()
            .set(encryption_network_key::ActiveModel {
                state: Set(KeyState::Active.as_str().to_string()),
                public_key: Set(public),
                sealed_seed: Set(sealed_seed),
                key_version: Set(row.key_version + 1),
                updated_at: Set(now_rfc3339()),
                ..Default::default()
            })
            .filter(encryption_network_key::Column::NetworkId.eq(row.network_id.clone()))
            .filter(encryption_network_key::Column::KeyPath.eq(row.key_path.clone()))
            .filter(encryption_network_key::Column::State.eq(KeyState::Deleted.as_str()))
            .filter(encryption_network_key::Column::KeyVersion.eq(row.key_version))
            .exec(tx)
            .await?;
        if updated.rows_affected != 1 {
            return Ok(CreateStep::Raced);
        }
        let row = find_key_row(tx, &network_of(loc)?, loc.path())
            .await?
            .ok_or(EncryptionServiceError::KeyNotFound)?;
        Ok(CreateStep::Reinstalled(row))
    }

    /// `key.block`. Idempotent; returns the descriptor. A deleted key is
    /// `key_deleted`. Does not check the network's state.
    pub async fn block_key(
        &self,
        loc: &KeyLocation,
    ) -> Result<KeyDescriptor, EncryptionServiceError> {
        self.set_key_state(loc, KeyState::Blocked).await
    }

    /// `key.unblock`. Idempotent; returns the descriptor. A deleted key is
    /// `key_deleted`. Does not check the network's state.
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
        let tx = begin_write_transaction(&self.db, None).await?;
        match self.set_key_state_in(&tx, &network, loc, target).await {
            Ok(row) => {
                tx.commit().await?;
                descriptor(row)
            }
            Err(err) => {
                let _ = tx.rollback().await;
                Err(err)
            }
        }
    }

    /// Under the network row lock: reads the row and writes the new state
    /// only while the stored state is `active` or `blocked`.
    async fn set_key_state_in(
        &self,
        tx: &DatabaseTransaction,
        network: &NetworkId,
        loc: &KeyLocation,
        target: KeyState,
    ) -> Result<encryption_network_key::Model, EncryptionServiceError> {
        lock_network_row(tx, network).await?;
        let row = find_key_row(tx, network, loc.path())
            .await?
            .ok_or(EncryptionServiceError::KeyNotFound)?;
        let checked = check_row(row)?;
        match checked.state {
            KeyState::Deleted => return Err(EncryptionServiceError::KeyDeleted),
            state if state == target => return Ok(checked.row),
            _ => {}
        }
        let updated = encryption_network_key::Entity::update_many()
            .col_expr(
                encryption_network_key::Column::State,
                Expr::value(target.as_str()),
            )
            .col_expr(
                encryption_network_key::Column::UpdatedAt,
                Expr::value(now_rfc3339()),
            )
            .filter(encryption_network_key::Column::NetworkId.eq(network.to_string()))
            .filter(encryption_network_key::Column::KeyPath.eq(loc.path()))
            .filter(
                encryption_network_key::Column::State
                    .is_in([KeyState::Active.as_str(), KeyState::Blocked.as_str()]),
            )
            .exec(tx)
            .await?;
        let row = find_key_row(tx, network, loc.path())
            .await?
            .ok_or(EncryptionServiceError::KeyNotFound)?;
        if updated.rows_affected != 1 {
            // The row left `active`/`blocked` before the write: answer from
            // what is stored now.
            return match check_row(row)?.state {
                KeyState::Deleted => Err(EncryptionServiceError::KeyDeleted),
                _ => Err(EncryptionServiceError::CorruptKeyRow),
            };
        }
        Ok(row)
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

    /// Unauthenticated public GET. Under `apps/` every path answers
    /// `key_not_found` without reading anything. Elsewhere it requires an
    /// ACTIVE network and always derives from the network secret, never from
    /// the stored row, so missing, blocked and active keys return identical
    /// output. Writes nothing and never reports key state or absence outside
    /// `apps/`.
    pub async fn public_key(&self, loc: &KeyLocation) -> Result<KeyPublic, EncryptionServiceError> {
        if is_apps_path(loc.path()) {
            return Err(EncryptionServiceError::KeyNotFound);
        }
        let network = network_of(loc)?;
        let net = load_active_network(&self.db, &network).await?;
        let sealed = net
            .sealed_private_key
            .as_deref()
            .ok_or(KeyBackendError::SealedKeyMissing)?;
        let network_secret = self.backend.open_network_secret(sealed)?;
        let public =
            self.backend
                .derive_named_public_key(&network_secret, &canonical_key_urn(loc), None)?;
        Ok(KeyPublic {
            network_id: network.to_string(),
            key_path: loc.path().to_string(),
            alg: ALG_X25519_AES256GCM.to_string(),
            key_version: KEY_VERSION_INITIAL,
            public_encryption_key: public,
        })
    }

    /// Release-guard state read and unwrap. Order: network ACTIVE, then key row
    /// exists and is ACTIVE, then (deletable keys) the requested key version
    /// equals the row's, then strict unwrap. Callers must invoke this after
    /// replay reservation. Any ECIES unwrap failure is `KeyUnwrapFailed`; a
    /// failure to unseal the network key is `Backend`; a seed that does not
    /// open strictly is `CorruptKeyRow`.
    pub async fn unwrap_named_key(
        &self,
        loc: &KeyLocation,
        wrapped_key: &[u8],
        requested_key_version: i64,
    ) -> Result<(i64, Vec<u8>), EncryptionServiceError> {
        let network = network_of(loc)?;
        let net = load_active_network(&self.db, &network).await?;
        let row = find_key_row(&self.db, &network, loc.path())
            .await?
            .ok_or(EncryptionServiceError::KeyNotFound)?;
        let CheckedRow { row, kind, state } = check_row(row)?;
        match state {
            KeyState::Active => {}
            KeyState::Blocked => return Err(EncryptionServiceError::KeyBlocked),
            KeyState::Deleted => return Err(EncryptionServiceError::KeyDeleted),
        }
        if kind == KeyKind::Deletable && row.key_version != requested_key_version {
            return Err(EncryptionServiceError::KeyDeleted);
        }
        let sealed = net
            .sealed_private_key
            .as_deref()
            .ok_or(KeyBackendError::SealedKeyMissing)?;
        let network_secret = self.backend.open_network_secret(sealed)?;
        let seed = match kind {
            KeyKind::Deterministic => None,
            KeyKind::Deletable => {
                let sealed_seed = row
                    .sealed_seed
                    .as_deref()
                    .ok_or(EncryptionServiceError::CorruptKeyRow)?;
                Some(
                    self.backend
                        .open_seed(sealed_seed)
                        .map_err(|_| EncryptionServiceError::CorruptKeyRow)?,
                )
            }
        };
        let symmetric = self
            .backend
            .unwrap_named(
                &network_secret,
                &canonical_key_urn(loc),
                seed.as_ref(),
                wrapped_key,
            )
            .map_err(EncryptionServiceError::KeyUnwrapFailed)?;
        Ok((row.key_version, symmetric))
    }
}

/// Startup check: no key row under `apps/` (or at the path `apps`) may be
/// anything other than a deletable key. Such a row cannot be read as a key,
/// and a path under `apps/` is only ever deletable.
pub async fn ensure_no_deterministic_app_keys<C: ConnectionTrait>(
    db: &C,
) -> Result<(), EncryptionServiceError> {
    let stray = encryption_network_key::Entity::find()
        .filter(
            Expr::cust("(key_path = 'apps' OR substr(key_path, 1, 5) = 'apps/')")
                .and(encryption_network_key::Column::Kind.ne(KeyKind::Deletable.as_str())),
        )
        .count(db)
        .await?;
    if stray == 0 {
        return Ok(());
    }
    Err(EncryptionServiceError::StrayAppKeyRows(stray))
}
