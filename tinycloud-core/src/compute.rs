//! P0 walking skeleton for the compute service (`tinycloud.compute/*`).
//!
//! See `specs/compute-service.md` (design) and
//! `specs/compute-service-implementation-plan.md` (P0 section) at the repo
//! root. This module intentionally holds only what P0 needs:
//!
//!   * `ComputeRequest` — the wire-format JSON request enum (§7.2), and its
//!     NORMATIVE request-variant -> required-ability mapping (§7.1 erratum,
//!     Codex C1). The mapping is enforced by the server dispatch
//!     (`tinycloud-node-server/src/routes/mod.rs::handle_compute_invoke`) via
//!     `policy_capability::ability_matches`.
//!   * `ComputeService` — a stub marker type, `.manage()`d by the server when
//!     the `compute` feature is enabled, exactly like `DuckDbService`. It
//!     carries no state yet; the artifact repository, backend registry, and
//!     routine-key derivation handle are P1/P2 additions.
//!
//! No variant has a live handler in P0 — the server rejects every variant
//! with `501 Not Implemented` once the ability-mapping gate passes. `List`
//! has no server-side handler in this plan at all (compute-service.md
//! §12.1/C9) and stays reserved indefinitely.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tinycloud_auth::resource::SpaceId;

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
        /// Encoded D_fn delegation header (MVP transport, compute-service.md
        /// §7.2/C7: JSON body + base64 WASM + inline encoded `D_fn` ONLY --
        /// raw streaming and pre-submitted grant CIDs are deferred).
        #[serde(default)]
        grant: Option<String>,
        /// Caveats for the deployed function (compute-service.md §10). The
        /// normative, camelCase-fielded shape -- NOT the enforced source of
        /// truth (§6.3: the enforced allowlist is chain-derived at execute
        /// time; this is the deploy-time declaration only).
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

/// Typed `ComputeCaveats` (compute-service.md §10, whitepaper
/// `appendix/appendix-j.md:104-112`). Deploy-time declaration only -- per
/// §6.3 the *enforced* allowlist at execute time is read from the validated
/// delegation chain, not trusted from invoker- or deployer-supplied facts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputeCaveats {
    /// Allowed function names (the `<function-path>` allowlist).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub functions: Option<Vec<String>>,
    /// Maximum execution time (ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration: Option<u64>,
    /// Maximum memory usage (bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory: Option<u64>,
    /// Input validation schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<serde_json::Value>,
}

/// The self-describing `D_fn` binding caveat (compute-service.md §5.1/§6.2,
/// DECIDED D2): `{ "computeFunctionBinding": { "functionCid": "<cid>" } }`.
/// Pinned as a function (not inlined per call site) because the exact JSON
/// shape is load-bearing -- the containment engine compares raw maps
/// byte-for-byte (§6.2/F1), so any drift between the deploy-time check and
/// the execute-time echo check fails closed.
pub fn compute_function_binding_caveat(function_cid: &str) -> serde_json::Value {
    serde_json::json!({ "computeFunctionBinding": { "functionCid": function_cid } })
}

/// The routine-key derivation input string (compute-service.md §6.2):
/// `"tinycloud/compute-key/v1/" + base32(blake3(space_canonical)) +
/// "/compute/" + function_cid`. The space component is HASHED (fixed-width,
/// lowercase, delimiter-free base32 of its blake3 digest) rather than
/// embedded raw, per Codex C8/defect a -- uniqueness does not depend on the
/// still-stubbed `Name` grammar (`tinycloud-auth/src/resource.rs`). Shared by
/// every `RoutineKeyDeriver` impl (classic here, dstack in the server crate)
/// so the two derivation paths can never drift.
pub fn routine_key_derivation_path(space: &SpaceId, function_cid: &str) -> String {
    let space_hash = crate::hash::hash(space.to_string().as_bytes());
    let space_token = tinycloud_auth::ipld_core::cid::multibase::encode(
        tinycloud_auth::ipld_core::cid::multibase::Base::Base32Lower,
        space_hash.as_ref(),
    );
    format!("tinycloud/compute-key/v1/{space_token}/compute/{function_cid}")
}

#[derive(Debug, thiserror::Error)]
pub enum RoutineKeyError {
    #[error("routine key derivation failed: {0}")]
    Derivation(String),
}

/// Routine execution identity derivation (compute-service.md §6.2). The
/// classic (`keys.rs` `StaticSecret`) impl lives here in core; the
/// dstack-TEE impl lives in the SERVER crate (`dstack::get_key` is
/// server-only -- core cannot reach the TEE socket, plan C11) and is
/// injected into the compute path at boot. Both impls MUST derive from
/// `routine_key_derivation_path` so a given (space, function_cid) resolves
/// to the same `routine_did` regardless of which impl produced it (modulo
/// the underlying secret material itself, which is impl-specific by
/// design -- D1).
#[async_trait::async_trait]
pub trait RoutineKeyDeriver: Send + Sync {
    /// Derive the routine's public `did:key` for `(space, function_cid)`.
    /// Read-only / side-effect-free -- safe to call repeatedly (the F2
    /// handshake, §6.2, and the F1.5 compare-on-execute tripwire both rely
    /// on this being idempotent).
    async fn derive_routine_did(
        &self,
        space: &SpaceId,
        function_cid: &str,
    ) -> Result<String, RoutineKeyError>;
}

/// Classic (non-TEE) routine key derivation: `StaticSecret::derive_key`
/// (`keys.rs:57-74`) keyed on the routine derivation path. The trust
/// statement weakens to "the node" rather than "this exact TEE" (§6.2, "Non-
/// TEE / classic mode").
pub struct ClassicRoutineKeyDeriver {
    secret: crate::keys::StaticSecret,
}

impl ClassicRoutineKeyDeriver {
    pub fn new(secret: crate::keys::StaticSecret) -> Self {
        Self { secret }
    }
}

#[async_trait::async_trait]
impl RoutineKeyDeriver for ClassicRoutineKeyDeriver {
    async fn derive_routine_did(
        &self,
        space: &SpaceId,
        function_cid: &str,
    ) -> Result<String, RoutineKeyError> {
        let path = routine_key_derivation_path(space, function_cid);
        let seed = self.secret.derive_key(path.as_bytes());
        crate::keys::ed25519_did_from_seed(seed)
            .map_err(|e| RoutineKeyError::Derivation(e.to_string()))
    }
}

/// The `ComputeService` handle, `.manage()`d by the server under
/// `#[cfg(feature = "compute")]`, exactly like `DuckDbService`
/// (compute-service.md §11.1). Holds the routine-key derivation handle
/// (P1); the backend registry (wasmtime + optional cloudflare) is a P2
/// addition. Unlike the sql/duckdb services, this does NOT need the
/// actor/idle-timeout machinery -- a function execution/deploy is
/// request-scoped, not a long-lived per-space connection.
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
    fn compute_service_holds_a_routine_key_deriver() {
        let secret = crate::keys::StaticSecret::new(vec![7u8; 32]).unwrap();
        let deriver: Arc<dyn RoutineKeyDeriver> = Arc::new(ClassicRoutineKeyDeriver::new(secret));
        let _ = ComputeService::new(deriver);
    }

    #[test]
    fn compute_caveats_round_trip_camel_case() {
        let json = r#"{"functions":["a","b"],"maxDuration":5000,"maxMemory":134217728,"inputs":{"type":"object"}}"#;
        let caveats: ComputeCaveats = serde_json::from_str(json).unwrap();
        assert_eq!(caveats.functions, Some(vec!["a".to_string(), "b".to_string()]));
        assert_eq!(caveats.max_duration, Some(5000));
        assert_eq!(caveats.max_memory, Some(134217728));
        assert!(caveats.inputs.is_some());
    }

    #[test]
    fn deploy_body_accepts_typed_caveats() {
        let deploy: ComputeRequest = serde_json::from_str(
            r#"{"action":"deploy","function":"report","wasm_b64":"AA==","caveats":{"maxDuration":1000}}"#,
        )
        .unwrap();
        match deploy {
            ComputeRequest::Deploy { caveats: Some(c), .. } => {
                assert_eq!(c.max_duration, Some(1000));
            }
            other => panic!("expected Deploy with typed caveats, got {other:?}"),
        }
    }
}
