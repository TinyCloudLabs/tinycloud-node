//! Server-crate `RoutineKeyDeriver` adapters (compute-service.md §6.2, plan
//! P1/C11).
//!
//! `tinycloud-core` defines the `RoutineKeyDeriver` trait and the classic
//! (`StaticSecret`) impl, but the dstack-TEE impl lives HERE because
//! `dstack::get_key` (`dstack.rs:106-119`) is server-only -- core cannot
//! reach the TEE Unix-domain-socket daemon. Both impls derive from the same
//! `tinycloud_core::compute::routine_key_derivation_path`, so a given
//! `(space, function_cid)` resolves identically regardless of which impl is
//! wired in at boot (modulo the underlying secret material, which is
//! impl-specific by design -- D1).

#![cfg(feature = "compute")]
#![cfg(feature = "dstack")]

use tinycloud_auth::resource::SpaceId;
use tinycloud_core::compute::{routine_key_derivation_path, RoutineKeyDeriver, RoutineKeyError};

/// dstack-TEE-backed routine key derivation. The private key is derived
/// inside the TEE and never leaves it (D1); this adapter only ever sees the
/// raw key bytes `dstack::get_key` returns, which it folds through blake3
/// into a 32-byte ed25519 seed (`get_key` does not itself promise an exact
/// 32-byte response shape, so this normalizes deterministically rather than
/// assuming one).
///
/// **Deployment-readiness note (compute-service.md §6.2 boxed warning, NOT
/// covered by this adapter or its unit tests):** this mechanism assumes
/// `dstack::get_key(path)` is STABLE for a given path across CVM redeploys.
/// That must be verified empirically on the target CVM (derive, redeploy,
/// re-derive, assert equality) before relying on derived-key identity in
/// production -- a prior DID-drift incident in OpenCredentials showed
/// dstack-derived key material shifting across deploys. Tracked as a
/// release precondition, not a test gate.
#[derive(Debug, Default, Clone, Copy)]
pub struct DstackRoutineKeyDeriver;

#[async_trait::async_trait]
impl RoutineKeyDeriver for DstackRoutineKeyDeriver {
    async fn derive_routine_did(
        &self,
        space: &SpaceId,
        function_cid: &str,
    ) -> Result<String, RoutineKeyError> {
        let path = routine_key_derivation_path(space, function_cid);
        let key_bytes = crate::dstack::get_key(&path)
            .await
            .map_err(|e| RoutineKeyError::Derivation(e.to_string()))?;
        let seed_hash = tinycloud_core::hash::hash(&key_bytes);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_hash.as_ref());
        tinycloud_core::keys::ed25519_did_from_seed(seed)
            .map_err(|e| RoutineKeyError::Derivation(e.to_string()))
    }
}
