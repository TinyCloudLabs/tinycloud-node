//! Compute service — P0 walking skeleton
//! (`specs/compute-service-implementation-plan.md`, `specs/compute-service.md`
//! §3/§7/§11).
//!
//! This module holds the wire types and the stub service handle that the
//! `compute` cargo feature gates on. The node-server crate owns the HTTP
//! dispatch (`tinycloud-node-server/src/routes/mod.rs`); this module owns the
//! request shape and the request-variant → ability mapping so it is testable
//! independent of Rocket.
//!
//! P0 does not execute, deploy, or list anything — every `ComputeRequest`
//! variant is accepted at the ability-mapping layer and then rejected with
//! "not implemented" by the server dispatch. P1 wires `RoutineDid`/`Deploy`;
//! P2 wires `Execute`. `List` stays unimplemented indefinitely (§3, deferred
//! to P4 — no server-side listing handler exists).

use serde::{Deserialize, Serialize};

/// A deployed function's declared data-access caveats (§6, §10.1). Opaque at
/// P0 — no caveat is enforced until P2 wires `WasmtimeBackend`. Kept as a
/// transparent JSON wrapper so `Deploy` bodies round-trip without imposing a
/// schema this phase does not yet enforce.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeCaveats(pub serde_json::Value);

/// Compute service request, decoded from the `POST /invoke` JSON body
/// (`specs/compute-service.md` §7.2). Mirrors `SqlRequest`/`DuckDbRequest`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ComputeRequest {
    /// Run a deployed function. Requires `tinycloud.compute/execute`.
    Execute {
        function: String,
        #[serde(default)]
        content_cid: Option<String>,
        #[serde(default)]
        input: Option<serde_json::Value>,
        #[serde(default)]
        input_refs: Option<Vec<String>>,
        #[serde(default)]
        output_ref: Option<String>,
    },
    /// Read-only handshake: the PUBLIC routine DID the node would derive for
    /// this (space, content_cid). Requires `tinycloud.compute/deploy` — it
    /// exists to let the client set `D_fn.delegatee` BEFORE deploy (§6.2/F2).
    RoutineDid { content_cid: String },
    /// Register / upload a new function version. Requires
    /// `tinycloud.compute/deploy`.
    Deploy {
        function: String,
        #[serde(default)]
        wasm_b64: Option<String>,
        #[serde(default)]
        grant: Option<String>,
        #[serde(default)]
        caveats: Option<ComputeCaveats>,
    },
    /// List deployed functions in the space. Requires
    /// `tinycloud.compute/list`. No server-side handler exists in the MVP
    /// (§3.1/C9) — always rejected as not-implemented.
    List,
}

impl ComputeRequest {
    /// Short tag for diagnostics/log messages — matches the wire `action`.
    pub fn action_name(&self) -> &'static str {
        match self {
            ComputeRequest::Execute { .. } => "execute",
            ComputeRequest::RoutineDid { .. } => "routine_did",
            ComputeRequest::Deploy { .. } => "deploy",
            ComputeRequest::List => "list",
        }
    }
}

/// Request-variant → required-ability mapping (NORMATIVE —
/// `specs/compute-service.md` §7.1 erratum, Codex C1). The dispatch layer
/// only proves the presented `tinycloud.compute/*` capability follows its
/// delegation chain; it does NOT tie the capability to the request body. The
/// caller MUST check the held ability against this required ability via
/// `policy_capability::ability_matches` (so an active `compute/*` wildcard
/// still covers all variants) and reject otherwise.
pub fn required_ability(request: &ComputeRequest) -> &'static str {
    match request {
        ComputeRequest::RoutineDid { .. } | ComputeRequest::Deploy { .. } => {
            "tinycloud.compute/deploy"
        }
        ComputeRequest::Execute { .. } => "tinycloud.compute/execute",
        ComputeRequest::List => "tinycloud.compute/list",
    }
}

/// Stub compute service handle. Holds nothing at P0 — the artifact repo,
/// backend registry, and routine-key derivation handle land in P1/P2
/// (`specs/compute-service.md` §11.1). Exists now so the server crate can
/// `.manage()` it and thread a `&State<ComputeService>` through dispatch,
/// mirroring `DuckDbService` registration.
#[derive(Debug, Default)]
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
            required_ability(&ComputeRequest::RoutineDid {
                content_cid: "bafy...".to_string()
            }),
            "tinycloud.compute/deploy"
        );
        assert_eq!(
            required_ability(&ComputeRequest::Deploy {
                function: "fn".to_string(),
                wasm_b64: None,
                grant: None,
                caveats: None,
            }),
            "tinycloud.compute/deploy"
        );
        assert_eq!(
            required_ability(&ComputeRequest::Execute {
                function: "fn".to_string(),
                content_cid: None,
                input: None,
                input_refs: None,
                output_ref: None,
            }),
            "tinycloud.compute/execute"
        );
        assert_eq!(
            required_ability(&ComputeRequest::List),
            "tinycloud.compute/list"
        );
    }

    #[test]
    fn compute_request_action_tag_round_trips() {
        let req: ComputeRequest =
            serde_json::from_str(r#"{"action":"execute","function":"report-generator"}"#).unwrap();
        assert!(matches!(req, ComputeRequest::Execute { .. }));
        assert_eq!(req.action_name(), "execute");

        let req: ComputeRequest = serde_json::from_str(r#"{"action":"list"}"#).unwrap();
        assert!(matches!(req, ComputeRequest::List));

        let req: ComputeRequest =
            serde_json::from_str(r#"{"action":"routine_did","content_cid":"bafy..."}"#).unwrap();
        assert!(matches!(req, ComputeRequest::RoutineDid { .. }));

        let req: ComputeRequest =
            serde_json::from_str(r#"{"action":"deploy","function":"fn"}"#).unwrap();
        assert!(matches!(req, ComputeRequest::Deploy { .. }));
    }
}
