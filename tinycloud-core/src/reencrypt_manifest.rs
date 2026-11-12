//! Canonical, separately hash-pinned public identities for offline migration.
use super::{select_batch, Error, Rings, COLUMNS};
use crate::encryption_network::{key_id::KeyLocation, NetworkId};
use sea_orm::{ConnectionTrait, TransactionTrait};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source_database: String,
    pub backup_id: String,
    pub snapshot_timestamp: String,
    pub snapshot_sha256: String,
    pub exported_by: String,
    pub storage_location: String,
    pub custody_record: String,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Network,
    Seed,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRow {
    pub kind: Kind,
    pub network_id: String,
    pub key_path: Option<String>,
    pub key_version: i64,
    pub public_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub version: u8,
    pub provenance: Provenance,
    pub rows: Vec<IdentityRow>,
}

type TrustedNetworkIdentities = BTreeMap<(String, i64), [u8; 32]>;
type TrustedSeedIdentities = BTreeMap<(String, String, i64), [u8; 32]>;

/// No public constructor or raw-map conversion: proof is checked before use.
#[derive(Clone)]
pub struct VerifiedManifest {
    networks: TrustedNetworkIdentities,
    seeds: TrustedSeedIdentities,
    digest: String,
}

fn hex32(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Manifest);
    }
    hex::decode(value)
        .map_err(|_| Error::Manifest)?
        .try_into()
        .map_err(|_| Error::Manifest)
}

impl VerifiedManifest {
    /// The expected digest must come from the custody record, separately from
    /// the supplied file. Hashing the untrusted file to choose this pin is invalid.
    pub fn verify(bytes: &[u8], expected_sha256: &str) -> Result<Self, Error> {
        hex32(expected_sha256)?;
        let digest = crate::encryption_network::canonical::hash_hex(bytes);
        if digest != expected_sha256 {
            return Err(Error::Manifest);
        }
        let doc: Document = serde_json::from_slice(bytes).map_err(|_| Error::Manifest)?;
        if serde_json::to_vec(&doc).map_err(|_| Error::Manifest)? != bytes || doc.version != 1 {
            return Err(Error::Manifest);
        }
        let p = &doc.provenance;
        if p.source_database != "tinycloud-node-production-usw"
            || [
                &p.backup_id,
                &p.exported_by,
                &p.storage_location,
                &p.custody_record,
            ]
            .iter()
            .any(|s| s.trim().is_empty())
        {
            return Err(Error::Manifest);
        }
        hex32(&p.snapshot_sha256)?;
        let date = time::OffsetDateTime::parse(
            &p.snapshot_timestamp,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| Error::Manifest)?;
        if date > time::OffsetDateTime::now_utc() {
            return Err(Error::Manifest);
        }
        if doc.rows.windows(2).any(|p| p[0] > p[1]) {
            return Err(Error::Manifest);
        }
        let mut manifest = Self {
            networks: BTreeMap::new(),
            seeds: BTreeMap::new(),
            digest,
        };
        for row in doc.rows {
            let network: NetworkId = row.network_id.parse().map_err(|_| Error::Manifest)?;
            if network.to_string() != row.network_id || row.key_version < 1 {
                return Err(Error::Manifest);
            }
            let public = hex32(&row.public_key)?;
            let duplicate = match (row.kind, row.key_path) {
                (Kind::Network, None) => manifest
                    .networks
                    .insert((row.network_id, row.key_version), public)
                    .is_some(),
                (Kind::Seed, Some(path)) => {
                    KeyLocation::new(&network, &path).map_err(|_| Error::Manifest)?;
                    manifest
                        .seeds
                        .insert((row.network_id, path, row.key_version), public)
                        .is_some()
                }
                _ => return Err(Error::Manifest),
            };
            if duplicate {
                return Err(Error::Manifest);
            }
        }
        Ok(manifest)
    }

    pub fn load(path: &Path, expected_sha256: &str) -> Result<Self, Error> {
        Self::verify(
            &std::fs::read(path).map_err(|_| Error::Manifest)?,
            expected_sha256,
        )
    }

    pub fn sha256(&self) -> &str {
        &self.digest
    }
    pub fn counts(&self) -> (usize, usize) {
        (self.networks.len(), self.seeds.len())
    }
    pub(super) fn network(&self, network: &str, version: i64) -> Option<&[u8; 32]> {
        self.networks.get(&(network.to_owned(), version))
    }
    pub(super) fn seed(&self, network: &str, path: &str, version: i64) -> Option<&[u8; 32]> {
        self.seeds
            .get(&(network.to_owned(), path.to_owned(), version))
    }
}

/// Counts only, including post-snapshot identities, never row identifiers.
#[derive(Debug, Default, Serialize)]
pub struct Coverage {
    pub missing_networks: u64,
    pub missing_seeds: u64,
    pub mismatched_networks: u64,
    pub mismatched_seeds: u64,
}
impl Coverage {
    pub fn blocked(&self) -> bool {
        self.missing_networks
            + self.missing_seeds
            + self.mismatched_networks
            + self.mismatched_seeds
            != 0
    }
}

pub async fn coverage<C: ConnectionTrait>(
    db: &C,
    proof: &VerifiedManifest,
) -> Result<Coverage, Error> {
    let mut counts = Coverage::default();
    // A DB row cannot erase a snapshot allocation by changing its version,
    // clearing it to pending, or disappearing entirely. No extra DB scan or
    // unbounded transaction is needed: remove exact identities as pages arrive.
    let mut unseen_networks: BTreeSet<_> = proof.networks.keys().cloned().collect();
    let mut unseen_seeds: BTreeSet<_> = proof.seeds.keys().cloned().collect();
    for (index, spec) in COLUMNS[..2].iter().enumerate() {
        let mut after = None;
        loop {
            let rows = select_batch(db, *spec, after.as_ref(), 128).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let previously_allocated = match (&row.key, row.key_version) {
                    (super::Key::Text(id), Some(version)) => proof.network(id, version).is_some(),
                    _ => false,
                };
                if index == 1
                    || previously_allocated
                    || row.blob.is_some()
                    || row.public_key.as_ref().is_some_and(|p| !p.is_empty())
                {
                    let version = row.key_version.ok_or(Error::Verify)?;
                    let expected = match &row.key {
                        super::Key::Text(id) => {
                            unseen_networks.remove(&(id.clone(), version));
                            proof.network(id, version)
                        }
                        super::Key::Pair(id, path) => {
                            unseen_seeds.remove(&(id.clone(), path.clone(), version));
                            proof.seed(id, path, version)
                        }
                        _ => return Err(Error::Verify),
                    };
                    match expected {
                        None if index == 0 => counts.missing_networks += 1,
                        None => counts.missing_seeds += 1,
                        Some(public) if Some(public.as_slice()) != row.public_key.as_deref() => {
                            if index == 0 {
                                counts.mismatched_networks += 1;
                            } else {
                                counts.mismatched_seeds += 1;
                            }
                        }
                        Some(_)
                            if index == 0
                                && (row.blob.as_ref().is_none_or(|b| b.is_empty())
                                    || !matches!(
                                        row.state.as_deref(),
                                        Some("active" | "rotating" | "revoked")
                                    )) =>
                        {
                            counts.missing_networks += 1;
                        }
                        _ => {}
                    }
                }
                after = Some(row.key);
            }
        }
    }
    counts.missing_networks += unseen_networks.len() as u64;
    counts.missing_seeds += unseen_seeds.len() as u64;
    Ok(counts)
}

/// Offline runner entry. Verify the file and separate pin before any DB call.
/// Serving must be stopped externally; root acquisition is supplied by the
/// rotation integration, never read from a new production configuration flag.
pub async fn run_offline<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    overlap: &Rings,
    path: &Path,
    expected_sha256: &str,
    batch: u64,
) -> Result<super::Progress, Error> {
    let proof = VerifiedManifest::load(path, expected_sha256)?;
    if batch == 0 || batch > 10000 {
        return Err(Error::Checkpoint);
    }
    let counts = coverage(db, &proof).await?;
    if counts.blocked() {
        return Err(Error::ManifestCoverage(counts));
    }
    let active = super::activate(db, overlap).await?;
    loop {
        let progress = super::step(db, &active, batch, &proof).await?;
        if progress.complete {
            return Ok(progress);
        }
    }
}
