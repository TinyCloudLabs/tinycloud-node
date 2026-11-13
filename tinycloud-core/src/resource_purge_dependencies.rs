//! Internal dependency identities. Raw identities are for the database only;
//! public dependency responses use keyed commitments computed by the controller.
use crate::{hash::Hash, resource_purge_fence::ResourceTarget};
use std::collections::BTreeSet;
use tinycloud_auth::ipld_core::cid::Cid;

#[derive(Clone, PartialEq, Eq)]
pub enum DependencyIdentity {
    Grant(Hash),
    Share(Hash),
    Member(String),
}

#[derive(thiserror::Error, Debug)]
#[error("invalid resource dependency snapshot")]
pub struct DependencySnapshotError;

impl DependencyIdentity {
    fn tagged(&self) -> (String, String) {
        match self {
            Self::Grant(hash) => ("grant".into(), hash.to_cid(0x55).to_string()),
            Self::Share(hash) => ("share".into(), hash.to_cid(0x55).to_string()),
            Self::Member(did) => ("member".into(), did.clone()),
        }
    }
    fn parse(tag: &str, identity: &str) -> Result<Self, DependencySnapshotError> {
        match tag {
            "grant" | "share" => {
                let cid: Cid = identity.parse().map_err(|_| DependencySnapshotError)?;
                let hash = Hash::from(cid);
                if hash.to_cid(0x55).to_string() != identity {
                    return Err(DependencySnapshotError);
                }
                Ok(if tag == "grant" {
                    Self::Grant(hash)
                } else {
                    Self::Share(hash)
                })
            }
            "member" => {
                let principal = tinycloud_auth::identity::principal_did(identity)
                    .map_err(|_| DependencySnapshotError)?;
                if principal != identity {
                    return Err(DependencySnapshotError);
                }
                Ok(Self::Member(identity.into()))
            }
            _ => Err(DependencySnapshotError),
        }
    }
}

/// Data only: decoding this type never authenticates a retirement or a reader.
/// No Debug/Serialize implementation exposes consumer identities accidentally.
#[derive(Clone)]
pub struct ResourceDependencySnapshot {
    target: ResourceTarget,
    identities: Vec<DependencyIdentity>,
}
/// A complete graph check may find grants whose recipient role is ambiguous.
/// Those grants cannot enable a reader exception or be reported as zero.
pub struct ResourceDependencyCheck {
    proven_outside: ResourceDependencySnapshot,
    ambiguous_grants: BTreeSet<Hash>,
}
impl ResourceDependencyCheck {
    pub fn proven_outside(&self) -> &ResourceDependencySnapshot {
        &self.proven_outside
    }
    pub fn proven_outside_count(&self) -> u64 {
        self.proven_outside.dependent_count()
    }
    pub fn ambiguous_count(&self) -> u64 {
        self.ambiguous_grants.len() as u64
    }
    /// Frozen wire count/fingerprint includes ambiguous grants. The separate
    /// ambiguous count stays internal and grants no reader provenance.
    pub fn fingerprint_identities(&self) -> Vec<DependencyIdentity> {
        let mut identities: std::collections::BTreeMap<_, _> = self
            .proven_outside
            .identities
            .iter()
            .cloned()
            .map(|identity| (identity.tagged(), identity))
            .collect();
        for hash in &self.ambiguous_grants {
            let identity = DependencyIdentity::Grant(*hash);
            identities.insert(identity.tagged(), identity);
        }
        identities.into_values().collect()
    }
    /// Persist the full retirement provenance union, including ambiguity.
    /// Membership alone never proves an outside-reader role.
    pub fn full_union_snapshot(
        &self,
    ) -> Result<ResourceDependencySnapshot, DependencySnapshotError> {
        ResourceDependencySnapshot::canonical(
            self.proven_outside.target.clone(),
            self.fingerprint_identities(),
        )
    }

    pub fn dependent_resource_count(&self) -> u64 {
        self.fingerprint_identities().len() as u64
    }

    pub fn is_verified_zero(&self) -> bool {
        self.proven_outside_count() == 0 && self.ambiguous_count() == 0
    }
}

impl ResourceDependencySnapshot {
    pub fn target(&self) -> &ResourceTarget {
        &self.target
    }
    pub fn identities(&self) -> &[DependencyIdentity] {
        &self.identities
    }
    pub fn dependent_count(&self) -> u64 {
        self.identities.len() as u64
    }

    /// Stable tagged canonical identities, suitable only for protected DB rows.
    pub fn to_db_bytes(&self) -> Result<Vec<u8>, DependencySnapshotError> {
        let rows: Vec<_> = self
            .identities
            .iter()
            .map(DependencyIdentity::tagged)
            .collect();
        serde_json::to_vec(&(self.target.as_str(), rows)).map_err(|_| DependencySnapshotError)
    }
    /// Require exact canonical order/encoding; this is not MAC verification.
    pub fn from_db_bytes(
        target: &ResourceTarget,
        bytes: &[u8],
    ) -> Result<Self, DependencySnapshotError> {
        let (raw_target, rows): (String, Vec<(String, String)>) =
            serde_json::from_slice(bytes).map_err(|_| DependencySnapshotError)?;
        if raw_target != target.as_str() {
            return Err(DependencySnapshotError);
        }
        let identities = rows
            .iter()
            .map(|(tag, id)| DependencyIdentity::parse(tag, id))
            .collect::<Result<Vec<_>, _>>()?;
        let snapshot = Self::canonical(target.clone(), identities)?;
        if snapshot.to_db_bytes()? != bytes {
            return Err(DependencySnapshotError);
        }
        Ok(snapshot)
    }
    /// Restrict a freshly validated graph result to pre-retirement provenance.
    /// Unexpected identities are refused rather than hidden from the checker.
    pub fn current_subset(&self, current: &Self) -> Result<Self, DependencySnapshotError> {
        if self.target.as_str() != current.target.as_str() {
            return Err(DependencySnapshotError);
        }
        let original: BTreeSet<_> = self
            .identities
            .iter()
            .map(DependencyIdentity::tagged)
            .collect();
        if current
            .identities
            .iter()
            .any(|identity| !original.contains(&identity.tagged()))
        {
            return Err(DependencySnapshotError);
        }
        Ok(current.clone())
    }

    fn canonical(
        target: ResourceTarget,
        identities: Vec<DependencyIdentity>,
    ) -> Result<Self, DependencySnapshotError> {
        let rows: BTreeSet<_> = identities.iter().map(DependencyIdentity::tagged).collect();
        let identities = rows
            .into_iter()
            .map(|(tag, id)| DependencyIdentity::parse(&tag, &id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { target, identities })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target(name: &str) -> ResourceTarget {
        ResourceTarget::parse(&format!("urn:tinycloud:encryption:did:pkh:eip155:1:0x1111111111111111111111111111111111111111:{name}")).unwrap()
    }
    #[test]
    fn stable_snapshot_deduplicates_tags_and_binds_target() {
        let hash = crate::hash::hash(b"synthetic authority");
        let snapshot = ResourceDependencySnapshot::canonical(
            target("default"),
            vec![
                DependencyIdentity::Share(hash),
                DependencyIdentity::Grant(hash),
                DependencyIdentity::Grant(hash),
            ],
        )
        .unwrap();
        assert_eq!(snapshot.dependent_count(), 2);
        let bytes = snapshot.to_db_bytes().unwrap();
        let restored =
            ResourceDependencySnapshot::from_db_bytes(&target("default"), &bytes).unwrap();
        assert_eq!(restored.to_db_bytes().unwrap(), bytes);
        assert!(ResourceDependencySnapshot::from_db_bytes(&target("other"), &bytes).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let duplicate = value[1][0].clone();
        value[1].as_array_mut().unwrap().push(duplicate);
        assert!(ResourceDependencySnapshot::from_db_bytes(
            &target("default"),
            &serde_json::to_vec(&value).unwrap()
        )
        .is_err());
    }
    #[test]
    fn ambiguity_is_in_frozen_count_fingerprint_and_persisted_union() {
        let grant = crate::hash::hash(b"ambiguous generic grant");
        let check = ResourceDependencyCheck {
            proven_outside: ResourceDependencySnapshot::canonical(target("default"), vec![])
                .unwrap(),
            ambiguous_grants: BTreeSet::from([grant]),
        };
        assert_eq!(check.proven_outside_count(), 0);
        assert_eq!(check.ambiguous_count(), 1);
        assert_eq!(check.dependent_resource_count(), 1);
        assert!(!check.is_verified_zero());
        assert!(
            matches!(check.fingerprint_identities().as_slice(), [DependencyIdentity::Grant(id)] if *id == grant)
        );
        let full = check.full_union_snapshot().unwrap();
        let restored = ResourceDependencySnapshot::from_db_bytes(
            &target("default"),
            &full.to_db_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(restored.dependent_count(), 1);
        let removed = ResourceDependencySnapshot::canonical(target("default"), vec![]).unwrap();
        assert!(restored.current_subset(&removed).is_ok());
        let added = ResourceDependencySnapshot::canonical(
            target("default"),
            vec![DependencyIdentity::Grant(crate::hash::hash(
                b"post retirement",
            ))],
        )
        .unwrap();
        assert!(restored.current_subset(&added).is_err());
    }

    #[test]
    fn uncertain_member_identity_is_refused() {
        assert!(DependencyIdentity::parse("member", "not a DID").is_err());
        assert!(DependencyIdentity::parse("unknown", "did:key:test").is_err());
    }
}
