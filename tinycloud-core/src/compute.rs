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

use serde::Deserialize;

/// The compute service's `POST /invoke` request body, mirroring
/// `SqlRequest`/`DuckDbRequest`'s tagged-enum `serde_json::from_str` dispatch
/// (compute-service.md §7.2).
#[derive(Debug, Clone, PartialEq, Deserialize)]
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
        /// Encoded D_fn delegation header (or its CID if pre-submitted).
        #[serde(default)]
        grant: Option<String>,
        /// Caveats for the deployed function. A typed `ComputeCaveats` lands
        /// with P1's real deploy handler; P0 only needs the mapping, not the
        /// shape.
        #[serde(default)]
        caveats: Option<serde_json::Value>,
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

/// P0 stub. Carries no state yet — the artifact repository, backend
/// registry (wasmtime + optional cloudflare), and routine-key derivation
/// handle are added when P1/P2 wire real handlers. `.manage()`d by the
/// server under `#[cfg(feature = "compute")]`, exactly like `DuckDbService`
/// (compute-service.md §11.1).
#[derive(Debug, Default, Clone, Copy)]
pub struct ComputeService;

impl ComputeService {
    pub fn new() -> Self {
        Self
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
    fn compute_service_is_a_stateless_stub() {
        let _ = ComputeService::new();
        let _ = ComputeService;
    }
}
