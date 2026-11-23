use super::*;
use crate::space_purge_fence::{FenceError, SpaceProbe, SpacePurgeFence};
use std::collections::BTreeMap;

pub(super) async fn probe<B: StorageSetup, K: Secrets, C: ConnectionTrait>(
    conn: &C,
    fence: Option<&SpacePurgeFence>,
    info: &crate::util::InvocationInfo,
    mode: InvokeMode,
) -> Result<(InvokeMode, Option<BTreeMap<SpaceId, SpaceProbe>>), TxError<B, K>> {
    let Some(fence) = fence else {
        return Ok((mode, None));
    };
    // Untyped core callers get the same envelope check before state lookup;
    // the admitted route skips this duplicate cryptographic operation.
    let mode = if mode == InvokeMode::Public {
        invocation::verify_invocation(&info.invocation)
            .await
            .map_err(TxError::<B, K>::from)?;
        InvokeMode::Admitted
    } else {
        mode
    };
    let mut probes = BTreeMap::new();
    for space in info.spaces() {
        if probes.contains_key(space) {
            continue;
        }
        let state = fence
            .probe(conn, space)
            .await
            .map_err(|err| database_error::<B, K>(err))?;
        if state.fenced
            && info.invoker.starts_with("did:pkh:")
            && did_principal_matches(space.did().as_str(), &info.invoker)
        {
            return Err(TxError::SpaceDeleted);
        }
        probes.insert(space.clone(), state);
    }
    Ok((mode, Some(probes)))
}
pub(super) fn refuse_absent<B: StorageSetup, K: Secrets>(
    probes: &Option<BTreeMap<SpaceId, SpaceProbe>>,
) -> Result<(), TxError<B, K>> {
    if probes
        .as_ref()
        .is_some_and(|states| states.values().any(|state| !state.exists || state.fenced))
    {
        return Err(TxError::SpaceNotFound);
    }
    Ok(())
}
pub(super) fn database_error<B: StorageSetup, K: Secrets>(error: FenceError) -> TxError<B, K> {
    match error {
        FenceError::Database(error) => TxError::Db(error),
        FenceError::Deleted => TxError::SpaceNotFound,
        FenceError::Unavailable => TxError::LifecycleUnavailable,
    }
}

/// Lock durable fence generations in the same metadata transaction as writes.
/// Call only AFTER the signed envelope and authority have been validated.
pub(super) async fn lock_live<B: StorageSetup, K: Secrets>(
    tx: &DatabaseTransaction,
    fence: Option<&SpacePurgeFence>,
    space: &SpaceId,
    actor: &str,
) -> Result<(), TxError<B, K>> {
    let Some(fence) = fence else {
        return Ok(());
    };
    match fence.lock_live(tx, space).await {
        Ok(()) => Ok(()),
        Err(FenceError::Deleted)
            if actor.starts_with("did:pkh:")
                && did_principal_matches(space.did().as_str(), actor) =>
        {
            Err(TxError::SpaceDeleted)
        }
        Err(error) => Err(database_error::<B, K>(error)),
    }
}

pub(super) async fn lock_delegation<B: StorageSetup, K: Secrets>(
    tx: &DatabaseTransaction,
    fence: Option<&SpacePurgeFence>,
    delegation: &Delegation,
) -> Result<(), TxError<B, K>> {
    for space in delegation.0.spaces() {
        match lock_live::<B, K>(tx, fence, space, &delegation.0.delegator).await {
            Err(TxError::SpaceNotFound) => {
                let parent = delegation
                    .0
                    .parents
                    .first()
                    .copied()
                    .unwrap_or_else(|| delegation.content_hash().to_cid(0x55));
                return Err(TxError::InvalidDelegation(
                    delegation::DelegationError::ParentRevoked(parent.to_string()),
                ));
            }
            other => other?,
        }
    }
    Ok(())
}
