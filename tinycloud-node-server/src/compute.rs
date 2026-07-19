//! Server-side compute wiring (compute-service.md §6.2, plan P1/Codex C11).
//!
//! The `RoutineKeyDeriver` TRAIT and the CLASSIC implementation live in
//! `tinycloud-core` (`compute.rs`). The DSTACK implementation lives HERE, in
//! the server crate, because `dstack::get_key` talks to the dstack daemon
//! over a Unix socket (`src/dstack.rs`) and is compiled only under the
//! server-only `dstack` feature -- `tinycloud-core` cannot call it directly.
//!
//! `build_routine_key_deriver` picks the impl at startup exactly like
//! `node_control::key_provider`'s identity split: dstack when the socket is
//! reachable, classic (`StaticSecret`) otherwise.

use std::sync::Arc;

use tinycloud_core::compute::{ClassicRoutineKeyDeriver, RoutineKeyDeriver};
use tinycloud_core::keys::StaticSecret;

/// The dstack `RoutineKeyDeriver` (compute-service.md §6.2, D1): derives the
/// routine seed INSIDE the TEE via `dstack::get_key`, so only this node,
/// running this exact function CID in this exact space, can act as the
/// routine. The private key never leaves the TEE.
#[cfg(feature = "dstack")]
pub struct DstackRoutineKeyDeriver;

#[cfg(feature = "dstack")]
impl DstackRoutineKeyDeriver {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "dstack")]
impl Default for DstackRoutineKeyDeriver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "dstack")]
#[async_trait::async_trait]
impl RoutineKeyDeriver for DstackRoutineKeyDeriver {
    async fn derive_routine_seed(
        &self,
        space: &tinycloud_auth::resource::SpaceId,
        function_cid: &str,
    ) -> Result<[u8; 32], tinycloud_core::compute::RoutineKeyError> {
        let path = tinycloud_core::compute::routine_key_derivation_path(space, function_cid);
        let key_bytes = crate::dstack::get_key(&path).await.map_err(|e| {
            tinycloud_core::compute::RoutineKeyError::DerivationFailed(e.to_string())
        })?;
        if key_bytes.len() < 32 {
            return Err(tinycloud_core::compute::RoutineKeyError::DerivationFailed(
                format!("dstack routine key too short: {} bytes", key_bytes.len()),
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&key_bytes[..32]);
        Ok(seed)
    }
}

/// Choose the routine-key deriver at startup. In TEE mode (dstack socket
/// reachable) the TEE-internal derivation is used; otherwise the classic
/// derivation runs off the node's static key material (`StaticSecret`,
/// `keys.rs`) -- the trust statement weakens to "the node" (§6.2 note on
/// classic mode).
pub fn build_routine_key_deriver(node_secret: &StaticSecret) -> Arc<dyn RoutineKeyDeriver> {
    #[cfg(feature = "dstack")]
    {
        if crate::dstack::is_available() {
            ::tracing::info!("compute: using dstack TEE routine-key derivation");
            return Arc::new(DstackRoutineKeyDeriver::new());
        }
    }
    Arc::new(ClassicRoutineKeyDeriver::new(node_secret.clone()))
}
