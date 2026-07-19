//! Compute service (`tinycloud.compute/*`): wire types, routine-key
//! derivation, and the service handle.
//!
//! See `specs/compute-service.md` (design) and
//! `specs/compute-service-implementation-plan.md` (P0/P1 sections) at the
//! repo root.
//!
//!   * `ComputeRequest` — the wire-format JSON request enum (§7.2), and its
//!     NORMATIVE request-variant -> required-ability mapping (§7.1 erratum,
//!     Codex C1). The mapping is enforced by the server dispatch
//!     (`tinycloud-node-server/src/routes/mod.rs::handle_compute_invoke`) via
//!     `policy_capability::ability_matches`.
//!   * `ComputeCaveats` — the normative, camelCase, fielded caveat shape
//!     (§10), replacing the P0 `serde_json::Value` placeholder.
//!   * `RoutineKeyDeriver` — the P1 trait (plan P1, Codex C11) that derives a
//!     routine's ed25519 seed for `(space, function_cid)` (§6.2). Lives here
//!     (core) with the CLASSIC implementation
//!     (`ClassicRoutineKeyDeriver`, `keys.rs`-style `StaticSecret::derive_key`);
//!     the DSTACK implementation lives in the SERVER crate
//!     (`tinycloud-node-server/src/dstack.rs::get_key` is server-only, so
//!     core cannot call it directly).
//!   * `ComputeService` — `.manage()`d by the server when the `compute`
//!     feature is enabled, exactly like `DuckDbService`. Holds the injected
//!     `RoutineKeyDeriver`; the backend registry (wasmtime + optional
//!     cloudflare) is a P2 addition.
//!
//! `Execute`/`List` have no live handler yet (P2 lands `Execute`; `List`
//! stays reserved indefinitely per §12.1/C9) — the server rejects those two
//! variants with `501 Not Implemented` once the ability-mapping gate passes.
//! `RoutineDid` and `Deploy` are P1's two live handlers.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tinycloud_auth::resource::SpaceId;

use crate::hash::hash;
use crate::keys::{public_key_to_did_key, StaticSecret};

/// The compute service's `POST /invoke` request body, mirroring
/// `SqlRequest`/`DuckDbRequest`'s tagged-enum `serde_json::from_str` dispatch
/// (compute-service.md §7.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ComputeRequest {
    /// Run a deployed function. Lands in P2.
    Execute {
        /// Function reference within the space (the `<function-path>` name).
        function: String,
        /// Optional exact content CID to pin (defense against a re-deploy
        /// race); when present the loaded artifact's content_hash must match.
        #[serde(default)]
        content_cid: Option<String>,
        /// Inline input, inlined in the request body.
        #[serde(default)]
        input: Option<serde_json::Value>,
        /// OR: read the input from these KV paths under the routine's own
        /// grant (§6.2).
        #[serde(default)]
        input_refs: Option<Vec<String>>,
        /// Optional output KV path; when present the result is written there
        /// instead of returned inline (§8).
        #[serde(default)]
        output_ref: Option<String>,
    },
    /// Read-only: return the PUBLIC routine DID the node would derive for
    /// this (space, content_cid). The F2 handshake step (§6.2). Lands in P1
    /// — requires `compute/deploy` exactly like `Deploy` (§7.1 erratum).
    RoutineDid { content_cid: String },
    /// Register / upload a new function version. Lands in P1.
    Deploy {
        function: String,
        #[serde(default)]
        wasm_b64: Option<String>,
        /// Encoded D_fn delegation header (MVP transport, §7.2/C7: JSON body
        /// + base64 WASM + an INLINE encoded `D_fn` only -- raw streaming
        /// and pre-submitted grant CIDs are deferred).
        #[serde(default)]
        grant: Option<String>,
        /// Caveats for the deployed function -- the normative, fielded
        /// shape (§10).
        #[serde(default)]
        caveats: Option<ComputeCaveats>,
    },
    /// List deployed functions in the space. No server-side handler exists
    /// or is planned in this plan (§12.1/C9) — stays reserved.
    List,
}

impl ComputeRequest {
    /// The NORMATIVE request-variant -> required-ability mapping
    /// (compute-service.md §7.1 erratum, Codex C1): `RoutineDid` and
    /// `Deploy` require `tinycloud.compute/deploy`; `Execute` requires
    /// `tinycloud.compute/execute`; `List` requires `tinycloud.compute/list`.
    ///
    /// The dispatch's capability filter only proves the presented
    /// `tinycloud.compute/*` capability follows a valid delegation chain; it
    /// does NOT tie the capability to the body. Callers MUST additionally
    /// check the held ability against this method's result (via
    /// `policy_capability::ability_matches`, so an active `compute/*`
    /// wildcard covers all) before dispatching on the variant.
    pub fn required_ability(&self) -> &'static str {
        match self {
            ComputeRequest::RoutineDid { .. } | ComputeRequest::Deploy { .. } => {
                "tinycloud.compute/deploy"
            }
            ComputeRequest::Execute { .. } => "tinycloud.compute/execute",
            ComputeRequest::List => "tinycloud.compute/list",
        }
    }
}

/// The normative, fielded caveat shape (compute-service.md §10, whitepaper
/// `appendix/appendix-j.md:104-112`). Per §6.3 the ENFORCED values come from
/// the validated delegation chain, not invoker facts -- this type is just
/// the shape both sides (chain caveat, invocation facts fallback) parse
/// into.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputeCaveats {
    /// Allowed function names (the `<function-path>` allowlist).
    #[serde(default)]
    pub functions: Option<Vec<String>>,
    /// Maximum execution time (ms).
    #[serde(default)]
    pub max_duration: Option<u64>,
    /// Maximum memory usage (bytes).
    #[serde(default)]
    pub max_memory: Option<u64>,
    /// Input validation schema.
    #[serde(default)]
    pub inputs: Option<serde_json::Value>,
}

/// Routine-key derivation error (P1, plan P1/Codex C11). Deliberately a
/// single, non-generic variant (rather than mirroring each backend's native
/// error type) so `RoutineKeyDeriver` stays dyn-compatible --
/// `ComputeService` holds `Arc<dyn RoutineKeyDeriver>` and swaps the CLASSIC
/// impl for the DSTACK impl (server crate) based on runtime TEE detection,
/// exactly like `node_control::key_provider`'s dstack/classic identity
/// split.
#[derive(Debug, thiserror::Error)]
pub enum RoutineKeyError {
    #[error("routine key derivation failed: {0}")]
    DerivationFailed(String),
}

/// Build the routine-key derivation path (compute-service.md §6.2, Codex
/// C8/defect a): `"tinycloud/compute-key/v1/" + base32(blake3(space)) +
/// "/compute/" + function_cid`. The space component is HASHED (fixed-width,
/// lowercase, delimiter-free base32 of its blake3 digest) rather than used
/// as a raw string, so uniqueness does NOT depend on the still-stubbed
/// `Name` grammar (`tinycloud-auth/src/resource.rs` `Name::try_from` is a
/// `// TODO` validator) -- two distinct spaces can never hash-collide into
/// one derivation string regardless of embedded delimiters in either
/// component. `function_cid` is already base32/delimiter-free (a CID), so it
/// rides unhashed.
pub fn routine_key_derivation_path(space: &SpaceId, function_cid: &str) -> String {
    let space_digest = hash(space.to_string().as_bytes());
    let hashed_space = data_encoding::BASE32_NOPAD
        .encode(space_digest.as_ref())
        .to_lowercase();
    format!("tinycloud/compute-key/v1/{hashed_space}/compute/{function_cid}")
}

/// Derive the ed25519 keypair's did:key from a raw 32-byte seed. NEVER
/// returns or logs the seed itself -- callers (the RoutineDid handshake,
/// §6.2/F2) must only ever surface the PUBLIC routine_did.
pub fn routine_did_from_seed(seed: [u8; 32]) -> Result<String, RoutineKeyError> {
    let ed_keypair = ed25519_keypair_from_seed(seed)?;
    let keypair: libp2p::identity::Keypair = ed_keypair.into();
    Ok(public_key_to_did_key(keypair.public()))
}

fn ed25519_keypair_from_seed(
    seed: [u8; 32],
) -> Result<libp2p::identity::ed25519::Keypair, RoutineKeyError> {
    let secret = libp2p::identity::ed25519::SecretKey::try_from_bytes(seed)
        .map_err(|e| RoutineKeyError::DerivationFailed(e.to_string()))?;
    Ok(libp2p::identity::ed25519::Keypair::from(secret))
}

/// Build an `ssi` JWK (OKP/Ed25519) from a raw 32-byte seed, so the routine
/// can sign as itself -- specifically the F1.5-adjacent "re-deploy hygiene"
/// self-revocation of a superseded `D_fn` (compute-service.md §5.1): the
/// delegatee of `D_fn` IS the routine_did, and `models/revocation.rs`'s
/// `revoker_is_authorized` accepts a delegatee self-revoke, so the node
/// (which holds this derived key) can sign the revocation itself without any
/// external proof.
pub fn routine_jwk_from_seed(
    seed: [u8; 32],
) -> Result<tinycloud_auth::ssi::jwk::JWK, RoutineKeyError> {
    use tinycloud_auth::ssi::jwk::{Base64urlUInt, Params, JWK};
    let keypair = ed25519_keypair_from_seed(seed)?;
    let public_bytes = keypair.public().to_bytes();
    Ok(JWK::from(Params::OKP(tinycloud_auth::ssi::jwk::OctetParams {
        curve: "Ed25519".to_string(),
        public_key: Base64urlUInt(public_bytes.to_vec()),
        private_key: Some(Base64urlUInt(seed.to_vec())),
    })))
}

/// P1 (plan P1, Codex C11): derives a routine's ed25519 seed for
/// `(space, function_cid)` (compute-service.md §6.2). Defined in CORE so it
/// can be injected server-side with either implementation:
///   * `ClassicRoutineKeyDeriver` (this module) -- `keys.rs`-style
///     `StaticSecret::derive_key`, for non-TEE deployments.
///   * The DSTACK implementation (`tinycloud-node-server`, `dstack.rs`) --
///     `dstack::get_key` runs the derivation INSIDE the TEE via a raw Unix
///     socket call, which is server-only, so core cannot call it directly.
///
/// Implementations MUST be deterministic (the same input always yields the
/// same seed) and MUST NOT expose the seed except via this trait's return
/// value -- callers that only need the public identity should call
/// `derive_routine_did`, never `derive_routine_seed` directly.
#[async_trait::async_trait]
pub trait RoutineKeyDeriver: Send + Sync {
    /// Derive the raw 32-byte ed25519 seed for the routine executing
    /// `function_cid` inside `space`. Callers MUST build the derivation
    /// input via `routine_key_derivation_path` (or pass it through
    /// unchanged) so every implementation derives from the SAME
    /// hashed-space, domain-separated path.
    async fn derive_routine_seed(
        &self,
        space: &SpaceId,
        function_cid: &str,
    ) -> Result<[u8; 32], RoutineKeyError>;

    /// Convenience: derive the seed and return only the PUBLIC routine_did.
    /// This is the only method the RoutineDid handshake (§6.2/F2) and the
    /// compare-on-execute tripwire (§6.2/F1.5) need.
    async fn derive_routine_did(
        &self,
        space: &SpaceId,
        function_cid: &str,
    ) -> Result<String, RoutineKeyError> {
        let seed = self.derive_routine_seed(space, function_cid).await?;
        routine_did_from_seed(seed)
    }
}

/// Classic (non-TEE) `RoutineKeyDeriver`: derives from the node's static
/// secret material via `StaticSecret::derive_key` (`keys.rs:70-78`), exactly
/// the same primitive `StaticSecret::node_did`/`Secrets::get_keypair` use for
/// other node-identity contexts. The trust statement is "the node" (not "the
/// TEE") -- see compute-service.md §6.2 note on classic mode.
pub struct ClassicRoutineKeyDeriver {
    secret: StaticSecret,
}

impl ClassicRoutineKeyDeriver {
    pub fn new(secret: StaticSecret) -> Self {
        Self { secret }
    }
}

#[async_trait::async_trait]
impl RoutineKeyDeriver for ClassicRoutineKeyDeriver {
    async fn derive_routine_seed(
        &self,
        space: &SpaceId,
        function_cid: &str,
    ) -> Result<[u8; 32], RoutineKeyError> {
        let path = routine_key_derivation_path(space, function_cid);
        Ok(self.secret.derive_key(path.as_bytes()))
    }
}

/// `.manage()`d by the server under `#[cfg(feature = "compute")]`, exactly
/// like `DuckDbService` (compute-service.md §11.1). Holds the injected
/// `RoutineKeyDeriver` (classic or dstack, chosen server-side at startup);
/// the backend registry (wasmtime + optional cloudflare) is a P2 addition.
#[derive(Clone)]
pub struct ComputeService {
    routine_key_deriver: Arc<dyn RoutineKeyDeriver>,
}

impl ComputeService {
    pub fn new(routine_key_deriver: Arc<dyn RoutineKeyDeriver>) -> Self {
        Self { routine_key_deriver }
    }

    pub fn routine_key_deriver(&self) -> &Arc<dyn RoutineKeyDeriver> {
        &self.routine_key_deriver
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_ability_mapping_matches_spec_7_1() {
        assert_eq!(
            ComputeRequest::RoutineDid {
                content_cid: "bafy".to_string()
            }
            .required_ability(),
            "tinycloud.compute/deploy"
        );
        assert_eq!(
            ComputeRequest::Deploy {
                function: "fn".to_string(),
                wasm_b64: None,
                grant: None,
                caveats: None,
            }
            .required_ability(),
            "tinycloud.compute/deploy"
        );
        assert_eq!(
            ComputeRequest::Execute {
                function: "fn".to_string(),
                content_cid: None,
                input: None,
                input_refs: None,
                output_ref: None,
            }
            .required_ability(),
            "tinycloud.compute/execute"
        );
        assert_eq!(
            ComputeRequest::List.required_ability(),
            "tinycloud.compute/list"
        );
    }

    #[test]
    fn wire_format_tags_on_action_snake_case() {
        let execute: ComputeRequest =
            serde_json::from_str(r#"{"action":"execute","function":"report"}"#).unwrap();
        assert!(
            matches!(execute, ComputeRequest::Execute { function, .. } if function == "report")
        );

        let routine_did: ComputeRequest =
            serde_json::from_str(r#"{"action":"routine_did","content_cid":"bafy123"}"#).unwrap();
        assert!(
            matches!(routine_did, ComputeRequest::RoutineDid { content_cid } if content_cid == "bafy123")
        );

        let deploy: ComputeRequest =
            serde_json::from_str(r#"{"action":"deploy","function":"report","wasm_b64":"AA=="}"#)
                .unwrap();
        assert!(
            matches!(deploy, ComputeRequest::Deploy { function, wasm_b64: Some(w), .. }
            if function == "report" && w == "AA==")
        );

        let list: ComputeRequest = serde_json::from_str(r#"{"action":"list"}"#).unwrap();
        assert_eq!(list, ComputeRequest::List);
    }

    #[test]
    fn compute_service_holds_an_injected_routine_key_deriver() {
        let deriver: Arc<dyn RoutineKeyDeriver> =
            Arc::new(ClassicRoutineKeyDeriver::new(StaticSecret::new(vec![7u8; 32]).unwrap()));
        let service = ComputeService::new(deriver);
        let _ = service.routine_key_deriver();
    }

    fn test_space_id(name: &str) -> SpaceId {
        use tinycloud_auth::{resolver::DID_METHODS, ssi::{dids::DIDBuf, jwk::JWK}};
        let jwk = JWK::generate_ed25519().unwrap();
        let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
        SpaceId::new(did, name.parse().unwrap())
    }

    #[tokio::test]
    async fn classic_routine_key_deriver_is_deterministic() {
        let secret = StaticSecret::new(vec![3u8; 32]).unwrap();
        let deriver = ClassicRoutineKeyDeriver::new(secret);
        let space = test_space_id("routine-key-determinism");

        let did1 = deriver.derive_routine_did(&space, "bafyfunctioncid").await.unwrap();
        let did2 = deriver.derive_routine_did(&space, "bafyfunctioncid").await.unwrap();
        assert_eq!(did1, did2, "same (space, function_cid) must derive the same routine_did");
        assert!(did1.starts_with("did:key:"));
    }

    #[tokio::test]
    async fn classic_routine_key_deriver_differs_by_function_cid() {
        let secret = StaticSecret::new(vec![3u8; 32]).unwrap();
        let deriver = ClassicRoutineKeyDeriver::new(secret);
        let space = test_space_id("routine-key-per-function");

        let did_a = deriver.derive_routine_did(&space, "bafyAAA").await.unwrap();
        let did_b = deriver.derive_routine_did(&space, "bafyBBB").await.unwrap();
        assert_ne!(did_a, did_b);
    }

    #[tokio::test]
    async fn classic_routine_key_deriver_hashed_space_prevents_delimiter_collision() {
        // Codex C8: two distinct spaces whose Display strings, if
        // concatenated raw with the function_cid, would collide across a
        // component boundary must NOT collide once the space component is
        // hashed. We can't construct two `SpaceId`s that concatenate to the
        // same string via the public API (`Name` has no delimiter
        // restrictions), so assert directly on the hashed derivation paths
        // for adversarially-chosen raw space strings that WOULD collide
        // under naive concatenation.
        let cid = "fn123";
        let space_a = "tinycloud:pkh:eip155:1:0xabc:my"; // + "/space" + cid below
        let space_b = "tinycloud:pkh:eip155:1:0xabc:my/space";
        // naive concat: space_a + "/" + "space" + cid == space_b + cid
        let naive_a = format!("{space_a}/space{cid}");
        let naive_b = format!("{space_b}{cid}");
        assert_eq!(naive_a, naive_b, "sanity: the naive concatenation DOES collide");

        let hash_a = super::hash(space_a.as_bytes());
        let hash_b = super::hash(space_b.as_bytes());
        assert_ne!(
            hash_a.as_ref(),
            hash_b.as_ref(),
            "hashed space components must not collide even when naive concatenation would"
        );
    }

    #[test]
    fn routine_key_derivation_path_is_fixed_width_and_delimiter_free() {
        let space = test_space_id("path-shape");
        let path = routine_key_derivation_path(&space, "bafyfunctioncid");
        assert!(path.starts_with("tinycloud/compute-key/v1/"));
        let hashed_segment = path
            .strip_prefix("tinycloud/compute-key/v1/")
            .unwrap()
            .split("/compute/")
            .next()
            .unwrap();
        // BASE32_NOPAD of a 32-byte blake3 digest is always 52 chars.
        assert_eq!(hashed_segment.len(), 52);
        assert!(hashed_segment
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert!(!hashed_segment.contains('/'));
        assert!(!hashed_segment.contains(':'));
    }
}
