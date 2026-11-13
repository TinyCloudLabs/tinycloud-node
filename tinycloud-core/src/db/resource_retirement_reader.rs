//! Narrow retired-owner read provenance; the resource lifetime/fence gate must
//! still consume this proof for the same invocation and exact target.
use super::*;
use crate::{
    resource_purge_dependencies::{
        collector::{
            decode as decode_dependency_grant, native_outside as native_outside_dependency,
        },
        DependencyIdentity,
    },
    resource_purge_fence::ResourceTarget,
    resource_retirement_snapshot::AuthenticatedRetirementSnapshot,
};
use std::{collections::HashSet, marker::PhantomData};
use tinycloud_auth::identity::did_principal_matches;

/// No public constructor, clone, serialization, or boolean authority input.
/// The borrowing transaction keeps the graph lock alive while this is used.
pub struct VerifiedOutsideResourceReader<'tx> {
    target: ResourceTarget,
    invocation: Hash,
    retirement: String,
    key_id: String,
    commitment: Vec<u8>,
    _transaction: PhantomData<&'tx DatabaseTransaction>,
}
impl VerifiedOutsideResourceReader<'_> {
    pub fn target(&self) -> &ResourceTarget {
        &self.target
    }
    pub fn invocation_hash(&self) -> Hash {
        self.invocation
    }
    pub fn retirement_id(&self) -> &str {
        &self.retirement
    }
    pub fn hmac_key_id(&self) -> &str {
        &self.key_id
    }
    pub fn commitment(&self) -> &[u8] {
        &self.commitment
    }
}
fn refused() -> invocation::Error {
    invocation::Error::Db(DbErr::Custom("outside resource reader unavailable".into()))
}
impl<C: ConnectionTrait, B, K: Secrets> SpaceDatabase<C, B, K> {
    /// Reuse normal renewal-aware authorization and require current positive
    /// recipient provenance inside the authenticated retirement snapshot.
    pub async fn authorize_retired_resource_reader<'tx>(
        &self,
        tx: &'tx DatabaseTransaction,
        admitted: &crate::AdmittedInvocation,
        target: &ResourceTarget,
        snapshot: &AuthenticatedRetirementSnapshot,
        now: OffsetDateTime,
    ) -> Result<VerifiedOutsideResourceReader<'tx>, invocation::Error> {
        let info = &admitted.invocation().0;
        if target.as_str() != snapshot.target().as_str()
            || info.capabilities.len() != 1
            || did_principal_matches(&info.invoker, target.owner_did())
        {
            return Err(refused());
        }
        let cap = &info.capabilities[0];
        if cap.resource.to_string() != target.as_str()
            || cap.ability.to_string() != crate::encryption_network::protocol::DECRYPT_ACTION
        {
            return Err(refused());
        }
        if self
            .secrets
            .renewal_seed()
            .is_some_and(|seed| crate::renewal::renewal_identity_from_seed(seed).0 == info.invoker)
        {
            return Err(
                invocation::InvocationError::UnauthorizedInvoker(info.invoker.clone()).into(),
            );
        }
        crate::space_purge_records::operation(tx).await?;
        let roots: Vec<_> = info.parents.iter().copied().map(Hash::from).collect();
        let graph =
            invocation_authorization_graph(tx, &roots, self.renewal_identity.as_ref(), now).await?;
        invocation::authorize_admitted(tx, info, now, Some(&graph), self.delegated_sql_caveats)
            .await?;
        let members: HashSet<Hash> = snapshot
            .snapshot()
            .identities()
            .iter()
            .filter_map(|identity| match identity {
                DependencyIdentity::Grant(hash) | DependencyIdentity::Share(hash) => Some(*hash),
                DependencyIdentity::Member(_) => None,
            })
            .collect();
        let mut positive = HashSet::new();
        for root in &roots {
            for id in graph.chain_ids_from(root) {
                // No newly registered descendant may inherit the exception
                // merely because some older ancestor was snapshotted.
                if !members.contains(&id) {
                    return Err(refused());
                }
                let row = graph.delegation(&id).ok_or_else(refused)?;
                let (bytes, delegation) = decode_dependency_grant(row, self.encryption.as_ref())?;
                if native_outside_dependency(tx, target, row, &bytes, &delegation).await? {
                    positive.insert(id);
                }
            }
        }
        if !graph.has_covering_path_to(
            roots,
            |ability| {
                cap.resource.extends(&ability.resource)
                    && crate::policy_capability::ability_matches(
                        ability.ability.as_ref().as_ref(),
                        cap.ability.as_ref().as_ref(),
                    )
                    && ability.caveats == cap.caveats
            },
            |row| members.contains(&row.id),
            |row| positive.contains(&row.id),
        ) {
            return Err(refused());
        }
        Ok(VerifiedOutsideResourceReader {
            target: target.clone(),
            invocation: admitted.invocation().content_hash(),
            retirement: snapshot.retirement_id().into(),
            key_id: snapshot.hmac_key_id().into(),
            commitment: snapshot.commitment().to_vec(),
            _transaction: PhantomData,
        })
    }
}
