//! Fenced, bounded and resumable storage re-encryption. No serving root selection.
use crate::encryption::{ColumnEncryption, RowBinding};
use crate::encryption_network::{
    backend::{KeyBackend, KeySeed, LocalOneOfOneBackend},
    key_id::KeyLocation,
    keys::canonical_key_urn,
    NetworkId,
};
use crate::hash::hash;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sea_orm::{ConnectionTrait, DbBackend, DbErr, QueryResult, Statement, TransactionTrait, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tinycloud_auth::{
    ipld_core::cid::Cid,
    multihash_codetable::{Code, MultihashDigest},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Future root acquisition boundary. No production implementation or config flag.
/// Implementations must return independent new material, never silently reuse ROOT.
pub trait NewRootSource {
    fn new_root(&self) -> Result<Zeroizing<[u8; 32]>, Error>;
}
#[derive(Clone)]
pub struct Rings {
    pub columns: ColumnEncryption,
    pub webhooks: ColumnEncryption,
    pub seals: ColumnEncryption,
}
/// Only hash-pinned, dated and custody-recorded manifests authorize migration.
#[path = "reencrypt_manifest.rs"]
pub mod manifest;
pub use manifest::VerifiedManifest;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid manifest proof: verify the file, pinned digest, date and custody record")]
    Manifest,
    #[error("manifest coverage blocks migration: {0:?}")]
    ManifestCoverage(manifest::Coverage),
    #[error("database operation failed")]
    Database,
    #[error("invalid re-encryption checkpoint or options")]
    Checkpoint,
    #[error("incompatible storage write generation")]
    Fence,
    #[error("storage decryption or verification failed")]
    Verify,
    #[error("plaintext integrity mismatch in {table}.{column}")]
    Integrity {
        table: &'static str,
        column: &'static str,
    },
    #[error("compare-and-swap conflict")]
    Conflict,
}
impl From<DbErr> for Error {
    fn from(_: DbErr) -> Self {
        Self::Database
    }
}

#[derive(Clone, Copy)]
enum Identity {
    Network,
    Seed,
    Webhook,
    Policy,
    Enforcement,
    Hash,
}

#[derive(Clone, Copy)]
struct Column {
    table: &'static str,
    column: &'static str,
    pk: &'static [&'static str],
    identity: Identity,
}

const COLUMNS: [Column; 7] = [
    Column {
        table: "encryption_network",
        column: "sealed_private_key",
        pk: &["network_id"],
        identity: Identity::Network,
    },
    Column {
        table: "encryption_network_key",
        column: "sealed_seed",
        pk: &["network_id", "key_path"],
        identity: Identity::Seed,
    },
    Column {
        table: "hook_subscription",
        column: "encrypted_secret",
        pk: &["id"],
        identity: Identity::Webhook,
    },
    Column {
        table: "owner_share_policy",
        column: "policy_bytes",
        pk: &["policy_cid"],
        identity: Identity::Policy,
    },
    Column {
        table: "owner_share_policy",
        column: "enforcement_delegation_bytes",
        pk: &["policy_cid"],
        identity: Identity::Enforcement,
    },
    Column {
        table: "delegation",
        column: "serialization",
        pk: &["id"],
        identity: Identity::Hash,
    },
    Column {
        table: "invocation",
        column: "serialization",
        pk: &["id"],
        identity: Identity::Hash,
    },
];

impl Column {
    fn format(self) -> Option<&'static str> {
        match self.column {
            "serialization" => Some("serialization_format"),
            "encrypted_secret" => Some("encrypted_secret_format"),
            "policy_bytes" => Some("policy_bytes_format"),
            "enforcement_delegation_bytes" => Some("enforcement_delegation_bytes_format"),
            _ => None,
        }
    }
    fn ring(self, rings: &Rings) -> &ColumnEncryption {
        match self.identity {
            Identity::Network | Identity::Seed => &rings.seals,
            Identity::Webhook => &rings.webhooks,
            _ => &rings.columns,
        }
    }
    fn binding<'a>(&self, pk: &'a [&'a [u8]]) -> RowBinding<'a> {
        RowBinding::new(self.table, self.column, pk)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Key {
    Text(String),
    Pair(String, String),
    Bytes(Vec<u8>),
}

impl Key {
    fn encoded(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|_| Error::Checkpoint)
    }

    fn values(&self) -> Vec<Value> {
        match self {
            Self::Text(value) => vec![value.clone().into()],
            Self::Pair(first, second) => vec![first.clone().into(), second.clone().into()],
            Self::Bytes(value) => vec![value.clone().into()],
        }
    }
}

struct Row {
    key: Key,
    blob: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    network_blob: Option<Vec<u8>>,
    network_public: Option<Vec<u8>>,
    network_version: Option<i64>,
    enforcement_cid: Option<String>,
    format: i16,
    state: Option<String>,
    kind: Option<String>,
    backend: Option<String>,
    key_version: Option<i64>,
}

// Only static SQL and fixed identifiers from COLUMNS reach this helper. Values
// are always bound, including bytea values and both parts of composite PKs.
fn bound(backend: DbBackend, sql: impl Into<String>, values: Vec<Value>) -> Statement {
    let sql = sql.into();
    if backend == DbBackend::Postgres {
        let mut parameter = 0;
        let sql = sql
            .split('?')
            .enumerate()
            .fold(String::new(), |mut result, (index, part)| {
                if index != 0 {
                    parameter += 1;
                    result.push('$');
                    result.push_str(&parameter.to_string());
                }
                result.push_str(part);
                result
            });
        Statement::from_sql_and_values(backend, sql, values)
    } else {
        Statement::from_sql_and_values(backend, sql, values)
    }
}

fn key_from_row(row: &QueryResult, spec: Column) -> Result<Key, Error> {
    Ok(if matches!(spec.identity, Identity::Hash) {
        Key::Bytes(row.try_get("", "pk0")?)
    } else if spec.pk.len() == 2 {
        Key::Pair(row.try_get("", "pk0")?, row.try_get("", "pk1")?)
    } else {
        Key::Text(row.try_get("", "pk0")?)
    })
}

async fn select_batch<C: ConnectionTrait>(
    db: &C,
    spec: Column,
    after: Option<&Key>,
    limit: u64,
) -> Result<Vec<Row>, Error> {
    let keys = spec
        .pk
        .iter()
        .enumerate()
        .map(|(i, key)| format!("t.{key} AS pk{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let format = spec
        .format()
        .map(|f| format!(", t.{f} AS format"))
        .unwrap_or_else(|| ", CAST(0 AS SMALLINT) AS format".into());
    let extra = match spec.identity {
        Identity::Network => ", t.public_key AS expected_public, t.state AS state, t.key_backend AS backend, t.key_version AS key_version",
        Identity::Seed => ", t.public_key AS expected_public, n.sealed_private_key AS network_blob, n.public_key AS network_public, n.key_version AS network_version, t.state AS state, t.kind AS kind, t.key_version AS key_version",
        Identity::Enforcement => ", t.enforcement_delegation_cid AS expected_cid",
        _ => "",
    };
    let join = if matches!(spec.identity, Identity::Seed) {
        " LEFT JOIN encryption_network n ON n.network_id = t.network_id"
    } else {
        ""
    };
    let mut values = Vec::new();
    let filter = match after {
        None => String::new(),
        Some(Key::Pair(first, second)) if spec.pk.len() == 2 => {
            values.extend([
                first.clone().into(),
                first.clone().into(),
                second.clone().into(),
            ]);
            format!(
                " WHERE (t.{} > ? OR (t.{} = ? AND t.{} > ?))",
                spec.pk[0], spec.pk[0], spec.pk[1]
            )
        }
        Some(key) if spec.pk.len() == 1 && !matches!(key, Key::Pair(_, _)) => {
            values.extend(key.values());
            format!(" WHERE t.{} > ?", spec.pk[0])
        }
        _ => return Err(Error::Checkpoint),
    };
    values.push((limit as i64).into());
    let order = spec
        .pk
        .iter()
        .map(|key| format!("t.{key}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT {keys}, t.{} AS blob{extra}{format} FROM {} t{join}{filter} ORDER BY {order} LIMIT ?",
        spec.column, spec.table
    );
    db.query_all(bound(db.get_database_backend(), sql, values))
        .await?
        .iter()
        .map(|row| {
            Ok(Row {
                format: row.try_get("", "format")?,
                state: if matches!(spec.identity, Identity::Network | Identity::Seed) {
                    Some(row.try_get("", "state")?)
                } else {
                    None
                },
                kind: if matches!(spec.identity, Identity::Seed) {
                    Some(row.try_get("", "kind")?)
                } else {
                    None
                },
                backend: if matches!(spec.identity, Identity::Network) {
                    Some(row.try_get("", "backend")?)
                } else {
                    None
                },
                key_version: if matches!(spec.identity, Identity::Network | Identity::Seed) {
                    Some(row.try_get("", "key_version")?)
                } else {
                    None
                },

                key: key_from_row(row, spec)?,
                blob: row.try_get("", "blob")?,
                public_key: if matches!(spec.identity, Identity::Network | Identity::Seed) {
                    Some(row.try_get("", "expected_public")?)
                } else {
                    None
                },
                network_blob: if matches!(spec.identity, Identity::Seed) {
                    row.try_get("", "network_blob")?
                } else {
                    None
                },
                network_public: if matches!(spec.identity, Identity::Seed) {
                    row.try_get("", "network_public")?
                } else {
                    None
                },
                network_version: if matches!(spec.identity, Identity::Seed) {
                    row.try_get("", "network_version")?
                } else {
                    None
                },
                enforcement_cid: if matches!(spec.identity, Identity::Enforcement) {
                    Some(row.try_get("", "expected_cid")?)
                } else {
                    None
                },
            })
        })
        .collect()
}

fn raw_sha256_cid(bytes: &[u8]) -> String {
    Cid::new_v1(0x55, Code::Sha2_256.digest(bytes)).to_string()
}

fn matches_raw_cid(expected: &str, bytes: &[u8]) -> bool {
    let Ok(expected) = expected.parse::<Cid>() else {
        return false;
    };
    if expected.codec() != 0x55 {
        return false;
    }
    match Code::try_from(expected.hash().code()) {
        Ok(code @ (Code::Sha2_256 | Code::Blake3_256)) => {
            Cid::new_v1(0x55, code.digest(bytes)) == expected
        }
        _ => false,
    }
}

// V1 seals have no row AAD. The migration alone may open them after checking
// external manifest evidence. Ceremonies are corroborative DB consistency only.
async fn legacy_network_consistency<C: ConnectionTrait>(
    db: &C,
    network: &str,
    public: &[u8],
    version: i64,
    trusted: &VerifiedManifest,
) -> Result<(), Error> {
    let mismatch = || Error::Integrity {
        table: "encryption_network",
        column: "sealed_private_key",
    };
    if trusted.network(network, version).map(|p| p.as_slice()) != Some(public) {
        return Err(mismatch());
    }
    let evidence=db.query_all(bound(db.get_database_backend(),"SELECT state,transcript_hash,completed_at,failure FROM encryption_ceremony WHERE network_id=? AND kind='initial' LIMIT 2",vec![network.into()])).await?;
    if evidence.len() != 1 {
        return Err(mismatch());
    }
    let row = &evidence[0];
    if row.try_get::<String>("", "state")? != "completed"
        || row
            .try_get::<Option<String>>("", "completed_at")?
            .is_none_or(|s| s.is_empty())
        || row.try_get::<Option<String>>("", "failure")?.is_some()
        || row
            .try_get::<Option<String>>("", "transcript_hash")?
            .as_deref()
            != Some(crate::encryption_network::canonical::hash_hex(public).as_str())
    {
        return Err(mismatch());
    }
    Ok(())
}

async fn migration_network_secret<C: ConnectionTrait>(
    db: &C,
    seal: &ColumnEncryption,
    network: &str,
    blob: &[u8],
    public: &[u8],
    version: i64,
    trusted: &VerifiedManifest,
) -> Result<StaticSecret, Error> {
    let opened = Zeroizing::new(
        if blob.first() == Some(&1) {
            legacy_network_consistency(db, network, public, version, trusted).await?;
            seal.decrypt_legacy(blob)
        } else {
            seal.decrypt_v2(
                blob,
                RowBinding::new(
                    "encryption_network",
                    "sealed_private_key",
                    &[network.as_bytes()],
                ),
            )
        }
        .map_err(|_| Error::Verify)?,
    );
    let bytes = Zeroizing::new(<[u8; 32]>::try_from(opened.as_slice()).map_err(|_| Error::Verify)?);
    let secret = StaticSecret::from(*bytes);
    if PublicKey::from(&secret).as_bytes().as_slice() != public {
        return Err(Error::Integrity {
            table: "encryption_network",
            column: "sealed_private_key",
        });
    }
    Ok(secret)
}

// NULL is accepted only for a lifecycle state that intentionally holds no
// sealed material. Required seals, invalid metadata and orphan key rows abort.
async fn validate_shape<C: ConnectionTrait>(
    db: &C,
    spec: Column,
    row: &Row,
    seal: &ColumnEncryption,
    trusted: &VerifiedManifest,
) -> Result<(), Error> {
    use crate::encryption_network::{key_id::KeyKind, types::NetworkState};
    match spec.identity {
        Identity::Network => {
            let Key::Text(id) = &row.key else {
                return Err(Error::Verify);
            };
            id.parse::<NetworkId>().map_err(|_| Error::Verify)?;
            let state = NetworkState::parse(row.state.as_deref().ok_or(Error::Verify)?)
                .ok_or(Error::Verify)?;
            if row.backend.as_deref() != Some("local-one-of-one")
                || row.key_version.is_none_or(|v| v < 1)
            {
                return Err(Error::Verify);
            }
            if row.blob.is_none() {
                if !matches!(
                    state,
                    NetworkState::Pending | NetworkState::Generating | NetworkState::Failed
                ) || row.public_key.as_deref() != Some(&[])
                {
                    return Err(Error::Verify);
                }
            } else if row.public_key.as_ref().is_none_or(|p| p.len() != 32) {
                return Err(Error::Verify);
            }
        }
        Identity::Seed => {
            let Key::Pair(network, path) = &row.key else {
                return Err(Error::Verify);
            };
            let network_id: NetworkId = network.parse().map_err(|_| Error::Verify)?;
            let location = KeyLocation::new(&network_id, path).map_err(|_| Error::Verify)?;
            let kind =
                KeyKind::parse(row.kind.as_deref().ok_or(Error::Verify)?).ok_or(Error::Verify)?;
            if kind != KeyKind::for_path(path)
                || !matches!(row.state.as_deref(), Some("active" | "blocked" | "deleted"))
                || row.key_version.is_none_or(|v| v < 1)
                || row.public_key.as_ref().is_none_or(|p| p.len() != 32)
            {
                return Err(Error::Verify);
            }
            let backend = LocalOneOfOneBackend::new(seal.clone());
            let secret = migration_network_secret(
                db,
                seal,
                network,
                row.network_blob.as_deref().ok_or(Error::Integrity {
                    table: spec.table,
                    column: spec.column,
                })?,
                row.network_public.as_deref().ok_or(Error::Verify)?,
                row.network_version.ok_or(Error::Verify)?,
                trusted,
            )
            .await?;
            match (kind, row.state.as_deref(), row.blob.is_some()) {
                (KeyKind::Deterministic, _, false) => {
                    let public = backend
                        .derive_named_public_key(&secret, &canonical_key_urn(&location), None)
                        .map_err(|_| Error::Verify)?;
                    if Some(public.as_slice()) != row.public_key.as_deref() {
                        return Err(Error::Verify);
                    }
                }
                (KeyKind::Deletable, Some("deleted"), false) => {}
                (KeyKind::Deletable, Some("active" | "blocked"), true) => {}
                _ => return Err(Error::Verify),
            }
        }
        _ if row.blob.is_none() => return Err(Error::Verify),
        _ => {}
    }
    Ok(())
}

async fn identity<C: ConnectionTrait>(
    db: &C,
    trusted: &VerifiedManifest,
    spec: Column,
    row: &Row,
    plaintext: &[u8],
    seal: &ColumnEncryption,
) -> Result<bool, Error> {
    let mismatch = || Error::Integrity {
        table: spec.table,
        column: spec.column,
    };
    match spec.identity {
        Identity::Webhook => Ok(false),
        Identity::Hash => {
            let Key::Bytes(expected) = &row.key else {
                return Err(mismatch());
            };
            let actual: Vec<u8> = hash(plaintext).into();
            if &actual != expected {
                return Err(mismatch());
            }
            Ok(true)
        }
        Identity::Policy => {
            let Key::Text(expected) = &row.key else {
                return Err(mismatch());
            };
            if &raw_sha256_cid(plaintext) != expected {
                return Err(mismatch());
            }
            Ok(true)
        }
        Identity::Enforcement => {
            let record: serde_json::Value =
                serde_json::from_slice(plaintext).map_err(|_| mismatch())?;
            let expected = row.enforcement_cid.as_deref().ok_or_else(mismatch)?;
            let cid = record
                .get("cid")
                .and_then(|value| value.as_str())
                .ok_or_else(mismatch)?;
            let bytes = record
                .get("dagCbor")
                .and_then(|value| value.as_str())
                .ok_or_else(mismatch)?;
            let bytes = URL_SAFE_NO_PAD.decode(bytes).map_err(|_| mismatch())?;
            if cid != expected || !matches_raw_cid(expected, &bytes) {
                return Err(mismatch());
            }
            // The stored JSON has additional uncommitted fields. The CID checks
            // the signed delegation bytes, not provenance of the entire record.
            Ok(false)
        }
        Identity::Network => {
            let bytes = Zeroizing::new(<[u8; 32]>::try_from(plaintext).map_err(|_| mismatch())?);
            let secret = StaticSecret::from(*bytes);
            if row.public_key.as_deref() != Some(PublicKey::from(&secret).as_bytes().as_slice()) {
                return Err(mismatch());
            }
            Ok(true)
        }
        Identity::Seed => {
            let bytes = Zeroizing::new(<[u8; 32]>::try_from(plaintext).map_err(|_| mismatch())?);
            let network_blob = row.network_blob.as_ref().ok_or_else(mismatch)?;
            let Key::Pair(network, path) = &row.key else {
                return Err(mismatch());
            };
            let secret = migration_network_secret(
                db,
                seal,
                network,
                network_blob,
                row.network_public.as_deref().ok_or_else(mismatch)?,
                row.network_version.ok_or_else(mismatch)?,
                trusted,
            )
            .await?;
            let expected = if row.blob.as_deref().is_some_and(|b| b.first() == Some(&1)) {
                Some(
                    trusted
                        .seed(network, path, row.key_version.ok_or_else(mismatch)?)
                        .ok_or_else(mismatch)?,
                )
            } else {
                None
            };
            let network: NetworkId = network.parse().map_err(|_| mismatch())?;
            let location = KeyLocation::new(&network, path).map_err(|_| mismatch())?;
            let backend = LocalOneOfOneBackend::new(seal.clone());
            let public = backend
                .derive_named_public_key(
                    &secret,
                    &canonical_key_urn(&location),
                    Some(&KeySeed::from_bytes(*bytes)),
                )
                .map_err(|_| mismatch())?;
            if expected.is_some_and(|expected| expected.as_slice() != public.as_slice()) {
                return Err(mismatch());
            }
            if row.public_key.as_deref() != Some(public.as_slice()) {
                return Err(mismatch());
            }
            Ok(true)
        }
    }
}

impl Rings {
    /// Inject the next ROOT while preserving the serving ROOT and v1 keys.
    pub fn from_source(
        source: &impl NewRootSource,
        old_root: [u8; 32],
        legacy_columns: [u8; 32],
        legacy_seal: [u8; 32],
    ) -> Result<Self, Error> {
        use crate::encryption::EncryptionPurpose;
        let old_root = Zeroizing::new(old_root);
        let legacy_columns = Zeroizing::new(legacy_columns);
        let legacy_seal = Zeroizing::new(legacy_seal);
        let new_root = source.new_root()?;
        if *new_root == *old_root {
            return Err(Error::Fence);
        }
        let make = |legacy, purpose| {
            ColumnEncryption::for_roots(
                if matches!(purpose, EncryptionPurpose::NetworkSeals) {
                    0
                } else {
                    1
                },
                if matches!(purpose, EncryptionPurpose::NetworkSeals) {
                    vec![(2, *new_root)]
                } else {
                    vec![(1, *old_root), (2, *new_root)]
                },
                legacy,
                purpose,
            )
            .map_err(|_| Error::Fence)
        };
        Ok(Self {
            columns: make(*legacy_columns, EncryptionPurpose::Columns)?,
            webhooks: make(*legacy_columns, EncryptionPurpose::Webhooks)?,
            seals: make(*legacy_seal, EncryptionPurpose::NetworkSeals)?,
        })
    }
    fn select_writer(&self, kid: u8) -> Result<Self, Error> {
        Ok(Self {
            columns: self.columns.for_kid(kid).map_err(|_| Error::Fence)?,
            webhooks: self.webhooks.for_kid(kid).map_err(|_| Error::Fence)?,
            seals: self.seals.for_kid(kid).map_err(|_| Error::Fence)?,
        })
    }
    fn overlap_readers(&self) -> bool {
        self.columns.has_exact_read_generations(&[1, 2], true)
            && self.webhooks.has_exact_read_generations(&[1, 2], true)
            && self.seals.has_exact_read_generations(&[0, 2], true)
    }
    fn overlap(&self) -> Result<(), Error> {
        if self.columns.write_kid() != 1
            || self.webhooks.write_kid() != 1
            || self.seals.write_kid() != 0
            || !self.overlap_readers()
        {
            return Err(Error::Fence);
        }
        Ok(())
    }
    fn kid(&self) -> Result<u8, Error> {
        let kid = self.columns.write_kid();
        if kid != 2 || self.webhooks.write_kid() != kid || self.seals.write_kid() != kid {
            return Err(Error::Fence);
        }
        Ok(kid)
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Count {
    pub table: &'static str,
    pub column: &'static str,
    pub legacy: u64,
    pub plaintext: u64,
    pub nulls: u64,
    pub kids: BTreeMap<u8, u64>,
}
/// Counts only; scans in bounded pages without logging row data.
pub async fn census<C: ConnectionTrait>(db: &C) -> Result<Vec<Count>, Error> {
    let mut counts = Vec::new();
    for spec in COLUMNS {
        let mut count = Count {
            table: spec.table,
            column: spec.column,
            ..Default::default()
        };
        let mut after = None;
        loop {
            let rows = select_batch(db, spec, after.as_ref(), 128).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                match row.blob.as_deref() {
                    None => count.nulls += 1,
                    Some(bytes)
                        if bytes.first() == Some(&1) && row.format == 0 && bytes.len() >= 29 =>
                    {
                        count.legacy += 1
                    }
                    Some(bytes) if bytes.first() == Some(&2) && bytes.len() >= 30 => {
                        *count.kids.entry(bytes[1]).or_default() += 1
                    }
                    Some(_) if row.format == 0 && spec.format().is_some() => count.plaintext += 1,
                    _ => return Err(Error::Verify),
                }
                after = Some(row.key);
            }
        }
        counts.push(count);
    }
    Ok(counts)
}

#[derive(Debug)]
pub struct Progress {
    pub rewritten: i64,
    pub verified: i64,
    pub verifying: bool,
    pub complete: bool,
}
pub async fn progress<C: ConnectionTrait>(db: &C) -> Result<Progress, Error> {
    let row = db
        .query_one(Statement::from_string(
            db.get_database_backend(),
            "SELECT rewritten, verified, phase, complete FROM storage_rekey WHERE id=1",
        ))
        .await?
        .ok_or(Error::Checkpoint)?;
    Ok(Progress {
        rewritten: row.try_get("", "rewritten")?,
        verified: row.try_get("", "verified")?,
        verifying: row.try_get::<i32>("", "phase")? == 1,
        complete: row.try_get("", "complete")?,
    })
}

/// Validate all serving rings against one locked database generation snapshot.
/// The caller holds its boot write transaction through alias validation.
pub async fn check_writer<C: ConnectionTrait>(
    db: &C,
    columns: Option<&ColumnEncryption>,
    webhooks: Option<&ColumnEncryption>,
    seals: Option<&ColumnEncryption>,
) -> Result<(), Error> {
    db.execute_unprepared("UPDATE storage_rekey SET target=target WHERE id=1")
        .await?;
    let row = db
        .query_one(Statement::from_string(
            db.get_database_backend(),
            "SELECT target FROM storage_rekey WHERE id=1",
        ))
        .await?
        .ok_or(Error::Checkpoint)?;
    let target: i32 = row.try_get("", "target")?;
    let options = [columns, webhooks, seals];
    if target == 0 {
        if columns.is_some_and(|r| r.write_kid() > 1)
            || webhooks.is_some_and(|r| r.write_kid() > 1)
            || seals.is_some_and(|r| r.write_kid() != 0)
        {
            return Err(Error::Fence);
        }
        if options.into_iter().flatten().any(|r| r.has_key(2)) {
            let rings = Rings {
                columns: columns.ok_or(Error::Fence)?.clone(),
                webhooks: webhooks.ok_or(Error::Fence)?.clone(),
                seals: seals.ok_or(Error::Fence)?.clone(),
            };
            rings.overlap()?;
        } else if webhooks.is_some() || seals.is_some() {
            // Normal serving, before any next ROOT is injected.
            if columns.is_none_or(|r| !r.has_exact_read_generations(&[1], true))
                || webhooks.is_none_or(|r| !r.has_exact_read_generations(&[1], true))
                || seals.is_none_or(|r| !r.has_exact_read_generations(&[0], true))
            {
                return Err(Error::Fence);
            }
        }
    } else if target == 2 {
        let rings = Rings {
            columns: columns.ok_or(Error::Fence)?.clone(),
            webhooks: webhooks.ok_or(Error::Fence)?.clone(),
            seals: seals.ok_or(Error::Fence)?.clone(),
        };
        rings.kid()?;
        if !rings.overlap_readers() {
            return Err(Error::Fence);
        }
    } else {
        return Err(Error::Fence);
    }

    Ok(())
}

fn filter(spec: Column) -> String {
    spec.pk
        .iter()
        .map(|k| format!("{k}=?"))
        .collect::<Vec<_>>()
        .join(" AND ")
}

/// Migration-owned guards keep generation 2 read-only until activation commits.
pub(crate) async fn pre_activation_guards<C: ConnectionTrait>(
    db: &C,
    install: bool,
) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    if !matches!(backend, DbBackend::Sqlite | DbBackend::Postgres) {
        return Ok(());
    }
    for (i, spec) in COLUMNS.iter().enumerate() {
        let column = spec.column;
        let table = spec.table;
        let name = format!("storage_rekey_overlap_{i}");
        if backend == DbBackend::Sqlite {
            for event in ["INSERT", "UPDATE"] {
                if install {
                    db.execute_unprepared(&format!("CREATE TRIGGER {name}_{event} BEFORE {event} ON {table} WHEN NEW.{column} IS NOT NULL AND substr(NEW.{column},1,2)=X'0202' AND (SELECT target FROM storage_rekey WHERE id=1)=0 BEGIN SELECT RAISE(ABORT,'storage generation fence'); END")).await?;
                } else {
                    db.execute_unprepared(&format!("DROP TRIGGER {name}_{event}"))
                        .await?;
                }
            }
        } else if install {
            db.execute_unprepared(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.{column} IS NOT NULL AND substring(NEW.{column} from 1 for 2)=decode('0202','hex') AND (SELECT target FROM storage_rekey WHERE id=1)=0 THEN RAISE EXCEPTION 'storage generation fence'; END IF; RETURN NEW; END $$")).await?;
            db.execute_unprepared(&format!("CREATE TRIGGER {name} BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION {name}()")).await?;
        } else {
            db.execute_unprepared(&format!("DROP TRIGGER {name} ON {table}"))
                .await?;
            db.execute_unprepared(&format!("DROP FUNCTION {name}()"))
                .await?;
        }
    }
    Ok(())
}

/// Atomically install a permanent database write fence and initialize progress.
/// All serving instances first install overlap readers with old writers.
/// Only after the fence commits does this return rings selecting the new writer.
/// Stale writers fail at the database boundary, including inserts behind cursors.
pub async fn activate<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    rings: &Rings,
) -> Result<Rings, Error> {
    let kid = 2u8;
    let tx = db.begin().await?;
    // A write obtains SQLite's writer reservation; PostgreSQL locks this singleton.
    tx.execute_unprepared("UPDATE storage_rekey SET target=target WHERE id=1")
        .await?;
    let state = tx
        .query_one(Statement::from_string(
            tx.get_database_backend(),
            "SELECT target FROM storage_rekey WHERE id=1",
        ))
        .await?
        .ok_or(Error::Checkpoint)?;
    let target: i32 = state.try_get("", "target")?;
    if target == i32::from(kid) {
        if !rings.overlap_readers() || (rings.overlap().is_err() && rings.kid().is_err()) {
            return Err(Error::Fence);
        }
        tx.commit().await?;
        return rings.select_writer(kid);
    }
    if target != 0 {
        return Err(Error::Fence);
    }
    rings.overlap()?;
    let backend = tx.get_database_backend();
    if !matches!(backend, DbBackend::Sqlite | DbBackend::Postgres) {
        return Err(Error::Fence);
    }
    for (i, spec) in COLUMNS.iter().enumerate() {
        let column = spec.column;
        let table = spec.table;
        let valid = if backend == DbBackend::Sqlite {
            format!("length(NEW.{column}) >= 30 AND substr(NEW.{column},1,2)=X'02{kid:02x}'")
        } else {
            format!("octet_length(NEW.{column}) >= 30 AND substring(NEW.{column} from 1 for 2)=decode('02{kid:02x}','hex')")
        };
        let valid = if let Some(fmt) = spec.format() {
            format!("({valid}) AND NEW.{fmt}=2")
        } else {
            valid
        };
        if backend == DbBackend::Sqlite {
            for event in ["INSERT", "UPDATE"] {
                let changed = if event == "UPDATE" {
                    format!(
                        " AND (NEW.{column} IS NOT OLD.{column}{} )",
                        spec.format()
                            .map(|f| format!(" OR NEW.{f} IS NOT OLD.{f}"))
                            .unwrap_or_default()
                    )
                } else {
                    String::new()
                };
                tx.execute_unprepared(&format!("CREATE TRIGGER storage_rekey_{i}_{event} BEFORE {event} ON {table} WHEN NEW.{column} IS NOT NULL{changed} AND NOT ({valid}) BEGIN SELECT RAISE(ABORT,'storage generation fence'); END")).await?;
            }
        } else {
            let changed = format!(
                "NEW.{column} IS DISTINCT FROM OLD.{column}{}",
                spec.format()
                    .map(|f| format!(" OR NEW.{f} IS DISTINCT FROM OLD.{f}"))
                    .unwrap_or_default()
            );
            tx.execute_unprepared(&format!("CREATE FUNCTION storage_rekey_{i}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.{column} IS NOT NULL AND (TG_OP='INSERT' OR {changed}) AND NOT ({valid}) THEN RAISE EXCEPTION 'storage generation fence'; END IF; RETURN NEW; END $$")).await?;
            tx.execute_unprepared(&format!("CREATE TRIGGER storage_rekey_{i} BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION storage_rekey_{i}()")).await?;
        }
    }
    // Any data mutation invalidates a paged verification snapshot. These updates
    // use the same singleton lock as each job page and boot validation.
    let mut tables =
        std::collections::BTreeSet::from(["delegation_cid_alias", "encryption_ceremony"]);
    tables.extend(COLUMNS.iter().map(|s| s.table));
    for (i, table) in tables.into_iter().enumerate() {
        if backend == DbBackend::Sqlite {
            for event in ["INSERT", "UPDATE", "DELETE"] {
                tx.execute_unprepared(&format!("CREATE TRIGGER storage_rekey_revision_{i}_{event} AFTER {event} ON {table} BEGIN UPDATE storage_rekey SET revision=revision+1, complete=FALSE WHERE id=1; END")).await?;
            }
        } else {
            tx.execute_unprepared(&format!("CREATE FUNCTION storage_rekey_revision_{i}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE storage_rekey SET revision=revision+1, complete=FALSE WHERE id=1; RETURN NULL; END $$")).await?;
            tx.execute_unprepared(&format!("CREATE TRIGGER storage_rekey_revision_{i} AFTER INSERT OR UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION storage_rekey_revision_{i}()")).await?;
        }
    }
    tx.execute(bound(
        backend,
        "UPDATE storage_rekey SET target=? WHERE id=1",
        vec![i32::from(kid).into()],
    ))
    .await?;
    tx.commit().await?;
    rings.select_writer(kid)
}

// Alias hashes are verified alongside the signed delegation that defines them.
async fn check_alias<C: ConnectionTrait>(
    db: &C,
    spec: Column,
    row: &Row,
    plain: &[u8],
    create: bool,
) -> Result<(), Error> {
    if spec.table != "delegation" {
        return Ok(());
    }
    let canonical: Vec<u8> = crate::models::delegation_cid_alias::canonical_hash(plain)
        .map_err(|_| Error::Verify)?
        .into();
    let Key::Bytes(id) = &row.key else {
        return Err(Error::Verify);
    };
    if create {
        db.execute(bound(db.get_database_backend(),"INSERT INTO delegation_cid_alias (id,canonical,encrypted) VALUES (?,?,TRUE) ON CONFLICT (id) DO NOTHING",vec![id.clone().into(),canonical.clone().into()])).await?;
    }
    let alias = db
        .query_one(bound(
            db.get_database_backend(),
            "SELECT canonical,encrypted FROM delegation_cid_alias WHERE id=?",
            vec![id.clone().into()],
        ))
        .await?
        .ok_or(Error::Verify)?;
    if alias.try_get::<Vec<u8>>("", "canonical")? != canonical
        || (!create && !alias.try_get::<bool>("", "encrypted")?)
    {
        return Err(Error::Verify);
    }
    Ok(())
}

/// One transaction, one bounded page. Dropping this future rolls the whole page
/// back; committed cursors and counters advance with the verified ciphertext.
pub async fn step<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    rings: &Rings,
    batch: u64,
    trusted: &VerifiedManifest,
) -> Result<Progress, Error> {
    step_page(
        db,
        rings,
        batch,
        trusted,
        #[cfg(test)]
        None,
    )
    .await
}

async fn step_page<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    rings: &Rings,
    batch: u64,
    trusted: &VerifiedManifest,
    #[cfg(test)] abort_after: Option<i64>,
) -> Result<Progress, Error> {
    if batch == 0 || batch > 10000 {
        return Err(Error::Checkpoint);
    }
    let kid = rings.kid()?;
    let tx = db.begin().await?;
    tx.execute_unprepared("UPDATE storage_rekey SET target=target WHERE id=1")
        .await?;
    let backend = tx.get_database_backend();
    let state=tx.query_one(Statement::from_string(backend,"SELECT target,column_index,cursor,phase,verified,revision,verify_revision FROM storage_rekey WHERE id=1")).await?.ok_or(Error::Checkpoint)?;
    if state.try_get::<i32>("", "target")? != i32::from(kid) {
        return Err(Error::Fence);
    }
    let mut index = state.try_get::<i32>("", "column_index")? as usize;
    let mut cursor: Option<String> = state.try_get("", "cursor")?;
    let phase = state.try_get::<i32>("", "phase")?;
    let verifying = phase == 1;
    if !matches!(phase, 0 | 1) || index > COLUMNS.len() {
        return Err(Error::Checkpoint);
    }
    let revision: i64 = state.try_get("", "revision")?;
    let snapshot: i64 = state.try_get("", "verify_revision")?;
    let mut verified = state.try_get::<i64>("", "verified")?;
    if verifying && revision != snapshot {
        // A serving write during verification requires a new complete pass.
        index = 0;
        cursor = None;
        verified = 0;
        tx.execute_unprepared("UPDATE storage_rekey SET column_index=0,cursor=NULL,verified=0,verify_revision=revision,complete=FALSE WHERE id=1").await?;
    }
    if index == COLUMNS.len() {
        if verifying {
            tx.execute_unprepared("UPDATE storage_rekey SET complete=TRUE WHERE id=1")
                .await?;
        } else {
            tx.execute_unprepared("UPDATE storage_rekey SET phase=1,column_index=0,cursor=NULL,verified=0,verify_revision=revision WHERE id=1").await?;
        }
        let report = progress(&tx).await?;
        tx.commit().await?;
        return Ok(report);
    }
    let after: Option<Key> = cursor
        .map(|v| serde_json::from_str(&v).map_err(|_| Error::Checkpoint))
        .transpose()?;
    let spec = COLUMNS[index];
    let rows = select_batch(&tx, spec, after.as_ref(), batch).await?;
    let mut done = 0i64;
    let mut last = None;
    for row in &rows {
        last = Some(row.key.encoded()?);
        validate_shape(&tx, spec, row, &rings.seals, trusted).await?;
        let Some(old) = &row.blob else {
            if verifying {
                verified += 1;
            }
            continue;
        };
        let keybytes: Vec<Vec<u8>> = match &row.key {
            Key::Bytes(b) => vec![b.clone()],
            Key::Text(s) => vec![s.as_bytes().to_vec()],
            Key::Pair(a, b) => vec![a.as_bytes().to_vec(), b.as_bytes().to_vec()],
        };
        let pk: Vec<&[u8]> = keybytes.iter().map(Vec::as_slice).collect();
        let binding = spec.binding(&pk);
        let ring = spec.ring(rings);
        let plain = Zeroizing::new(
            if spec.format().is_some() {
                ring.decrypt_recorded(old, binding, row.format)
            } else if old.first() == Some(&1) {
                if matches!(spec.identity, Identity::Network) {
                    let Key::Text(network) = &row.key else {
                        return Err(Error::Verify);
                    };
                    legacy_network_consistency(
                        &tx,
                        network,
                        row.public_key.as_deref().ok_or(Error::Verify)?,
                        row.key_version.ok_or(Error::Verify)?,
                        trusted,
                    )
                    .await?;
                }
                ring.decrypt_legacy(old)
            } else {
                ring.decrypt_v2(old, binding)
            }
            .map_err(|_| Error::Verify)?,
        );
        identity(&tx, trusted, spec, row, &plain, &rings.seals).await?;
        if verifying {
            if old.get(..2) != Some(&[2, kid]) || (spec.format().is_some() && row.format != 2) {
                return Err(Error::Verify);
            }
            check_alias(&tx, spec, row, &plain, false).await?;
            verified += 1;
            #[cfg(test)]
            if abort_after == Some(verified - state.try_get::<i64>("", "verified")?) {
                return Err(Error::Verify);
            }
            continue;
        }
        check_alias(&tx, spec, row, &plain, true).await?;
        if old.get(..2) == Some(&[2, kid]) && (spec.format().is_none() || row.format == 2) {
            continue;
        }
        let new = ring.encrypt(&plain, binding);
        let mut values = vec![new.clone().into()];
        values.extend(row.key.values());
        values.push(old.clone().into());
        let format_set = spec
            .format()
            .map(|f| format!(", {f}=2"))
            .unwrap_or_default();
        let format_cas = spec
            .format()
            .map(|f| {
                values.push(row.format.into());
                format!(" AND {f}=?")
            })
            .unwrap_or_default();
        let updated = tx
            .execute(bound(
                backend,
                format!(
                    "UPDATE {} SET {}=?{format_set} WHERE {} AND {}=?{format_cas}",
                    spec.table,
                    spec.column,
                    filter(spec),
                    spec.column
                ),
                values,
            ))
            .await?;
        if updated.rows_affected() != 1 {
            return Err(Error::Conflict);
        }
        if spec.table == "delegation" {
            tx.execute(bound(
                backend,
                "UPDATE delegation_cid_alias SET encrypted=TRUE WHERE id=?",
                row.key.values(),
            ))
            .await?;
        }

        let saved = tx
            .query_one(bound(
                backend,
                format!(
                    "SELECT {} AS blob FROM {} WHERE {}",
                    spec.column,
                    spec.table,
                    filter(spec)
                ),
                row.key.values(),
            ))
            .await?
            .ok_or(Error::Conflict)?;
        let saved: Vec<u8> = saved.try_get("", "blob")?;
        if saved != new
            || Zeroizing::new(
                ring.decrypt_v2(&saved, binding)
                    .map_err(|_| Error::Verify)?,
            )
            .as_slice()
                != plain.as_slice()
        {
            return Err(Error::Verify);
        }
        identity(&tx, trusted, spec, row, &plain, &rings.seals).await?;
        done += 1;
        #[cfg(test)]
        if abort_after == Some(done) {
            return Err(Error::Verify);
        }
    }
    let next = if rows.is_empty() { index + 1 } else { index };
    tx.execute(bound(backend,"UPDATE storage_rekey SET column_index=?,cursor=?,rewritten=rewritten+?,verified=?,complete=FALSE WHERE id=1",vec![(next as i32).into(),last.into(),done.into(),verified.into()])).await?;
    let report = progress(&tx).await?;
    tx.commit().await?;
    Ok(report)
}

#[cfg(test)]
#[path = "reencrypt_tests.rs"]
mod tests;
