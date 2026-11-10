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
#[derive(Debug, thiserror::Error)]
pub enum Error {
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
        match self.identity {
            Identity::Network => crate::encryption_network::backend::NETWORK_SEAL_BINDING,
            Identity::Seed => crate::encryption_network::backend::SEED_SEAL_BINDING,
            _ => RowBinding::new(self.table, self.column, pk),
        }
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
    enforcement_cid: Option<String>,
    format: i16,
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
        Identity::Network => ", t.public_key AS expected_public",
        Identity::Seed => ", t.public_key AS expected_public, n.sealed_private_key AS network_blob, n.public_key AS network_public",
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

fn identity(
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
            let Some(network_blob) = &row.network_blob else {
                return Ok(false);
            };
            let network_bytes = Zeroizing::new(
                seal.decrypt(
                    network_blob,
                    crate::encryption_network::backend::NETWORK_SEAL_BINDING,
                )
                .map_err(|_| mismatch())?,
            );
            let network_bytes = Zeroizing::new(
                <[u8; 32]>::try_from(network_bytes.as_slice()).map_err(|_| mismatch())?,
            );
            let secret = StaticSecret::from(*network_bytes);
            if row.network_public.as_deref() != Some(PublicKey::from(&secret).as_bytes().as_slice())
            {
                return Err(mismatch());
            }
            let Key::Pair(network, path) = &row.key else {
                return Err(mismatch());
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
            ColumnEncryption::for_roots(2, [(1, *old_root), (2, *new_root)], legacy, purpose)
                .map_err(|_| Error::Fence)
        };
        Ok(Self {
            columns: make(*legacy_columns, EncryptionPurpose::Columns)?,
            webhooks: make(*legacy_columns, EncryptionPurpose::Webhooks)?,
            seals: make(*legacy_seal, EncryptionPurpose::NetworkSeals)?,
        })
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
    pub complete: bool,
}
pub async fn progress<C: ConnectionTrait>(db: &C) -> Result<Progress, Error> {
    let row = db
        .query_one(Statement::from_string(
            db.get_database_backend(),
            "SELECT rewritten, complete FROM storage_rekey WHERE id=1",
        ))
        .await?
        .ok_or(Error::Checkpoint)?;
    Ok(Progress {
        rewritten: row.try_get("", "rewritten")?,
        complete: row.try_get("", "complete")?,
    })
}
/// Reject stale/keyless boot after activation; triggers also fence live writers.
pub async fn check_writer<C: ConnectionTrait>(
    db: &C,
    ring: Option<&ColumnEncryption>,
) -> Result<(), Error> {
    let row = db
        .query_one(Statement::from_string(
            db.get_database_backend(),
            "SELECT target FROM storage_rekey WHERE id=1",
        ))
        .await?
        .ok_or(Error::Checkpoint)?;
    let target: i32 = row.try_get("", "target")?;
    if target != 0 && ring.map(|r| i32::from(r.write_kid())) != Some(target) {
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

/// Atomically install a permanent database write fence and initialize progress.
/// All serving instances must already hold both roots before calling this API.
/// Stale writers fail at the database boundary, including inserts behind cursors.
pub async fn activate<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    rings: &Rings,
) -> Result<(), Error> {
    let kid = rings.kid()?;
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
        tx.commit().await?;
        return Ok(());
    }
    if target != 0 {
        return Err(Error::Fence);
    }
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
    tx.execute(bound(
        backend,
        "UPDATE storage_rekey SET target=? WHERE id=1",
        vec![i32::from(kid).into()],
    ))
    .await?;
    tx.commit().await?;
    Ok(())
}

/// One transaction, one bounded page. Dropping this future rolls the whole page
/// back; committed cursors and counters advance with the verified ciphertext.
pub async fn step<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    rings: &Rings,
    batch: u64,
) -> Result<Progress, Error> {
    step_page(
        db,
        rings,
        batch,
        #[cfg(test)]
        None,
    )
    .await
}

async fn step_page<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    rings: &Rings,
    batch: u64,
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
    let state = tx
        .query_one(Statement::from_string(
            backend,
            "SELECT target, column_index, cursor, rewritten FROM storage_rekey WHERE id=1",
        ))
        .await?
        .ok_or(Error::Checkpoint)?;
    if state.try_get::<i32>("", "target")? != i32::from(kid) {
        return Err(Error::Fence);
    }
    let index = state.try_get::<i32>("", "column_index")? as usize;
    let cursor: Option<String> = state.try_get("", "cursor")?;
    let after: Option<Key> = cursor
        .map(|v| serde_json::from_str(&v).map_err(|_| Error::Checkpoint))
        .transpose()?;
    let rewritten: i64 = state.try_get("", "rewritten")?;
    if index >= COLUMNS.len() {
        // Fence prevents new old-kid rows; verify every value, even already-target
        // rows, before declaring completion. Reset to a fresh pass for idempotence.
        let remaining = census(&tx).await?;
        if remaining
            .iter()
            .any(|c| c.legacy > 0 || c.plaintext > 0 || c.kids.keys().any(|k| *k != kid))
        {
            return Err(Error::Verify);
        }
        tx.execute_unprepared("UPDATE storage_rekey SET complete=TRUE WHERE id=1")
            .await?;
        tx.commit().await?;
        return Ok(Progress {
            rewritten,
            complete: true,
        });
    }
    let spec = COLUMNS[index];
    let rows = select_batch(&tx, spec, after.as_ref(), batch).await?;
    let mut done = 0i64;
    let mut last = None;
    for row in &rows {
        last = Some(row.key.encoded()?);
        let Some(old) = &row.blob else {
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
            } else {
                ring.decrypt(old, binding)
            }
            .map_err(|_| Error::Verify)?,
        );
        identity(spec, row, &plain, &rings.seals)?;
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
            || Zeroizing::new(ring.decrypt(&saved, binding).map_err(|_| Error::Verify)?).as_slice()
                != plain.as_slice()
        {
            return Err(Error::Verify);
        }
        identity(spec, row, &plain, &rings.seals)?;
        done += 1;
        #[cfg(test)]
        if abort_after == Some(done) {
            return Err(Error::Verify);
        }
    }
    let next = if rows.is_empty() { index + 1 } else { index };
    tx.execute(bound(backend,"UPDATE storage_rekey SET column_index=?, cursor=?, rewritten=rewritten+?, complete=FALSE WHERE id=1",vec![(next as i32).into(),last.into(),done.into()])).await?;
    tx.commit().await?;
    Ok(Progress {
        rewritten: rewritten + done,
        complete: false,
    })
}

#[cfg(test)]
#[path = "reencrypt_tests.rs"]
mod tests;
