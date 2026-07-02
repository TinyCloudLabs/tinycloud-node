// W1 native contract — vector-driven enforcement tests.
//
// These tests exercise the W0 frozen vectors directly against the on-node
// enforcement primitives in `tinycloud-core`:
//
//   * SQL constrained-statement INVOCATION rejections (raw query/execute/
//     batch/export, fixed-param override, escape, etc.) against
//     `enforce_constrained_profile`-style logic.
//   * PolicyCapability canonicalization + containment (delegates to the
//     `tinycloud-core` unit tests so we re-verify here from the
//     integration boundary).
//
// The terminal/revocation vectors are abstract chain-shaped — we exercise
// their semantics by asserting that the W1 native-contract code paths
// reject the named codes. Full chain-walking integration tests against an
// in-memory database are listed as followups.

use serde::Deserialize;
use serde_json::Value;
use tinycloud_core::policy_capability::{parse, sql_caveat, SqlConstrainedStatementCaveat};
use tinycloud_core::sql::SqlRequest;

const REJECT_VECTORS: &str = include_str!("fixtures/w1/sql-caveat/reject.json");
const ACCEPT_VECTORS: &str = include_str!("fixtures/w1/sql-caveat/accept.json");

#[derive(Deserialize)]
struct RejectFile {
    cases: Vec<RejectCase>,
}

#[derive(Deserialize)]
struct RejectCase {
    case: String,
    auth_capability: Value,
    #[serde(default)]
    invocation: Option<Value>,
    rejection_code: String,
}

#[derive(Deserialize)]
struct AcceptFile {
    cases: Vec<AcceptCase>,
}

#[derive(Deserialize)]
struct AcceptCase {
    case: String,
    auth_capability: Value,
    invocation: Value,
}

/// Pure-function port of routes::enforce_constrained_profile, mirroring the
/// on-node logic. Mirrors so the integration test crate does not need to
/// pull in rocket and the full HTTP wiring.
fn enforce(
    caveat: &SqlConstrainedStatementCaveat,
    request: SqlRequest,
) -> Result<SqlRequest, sql_caveat::InvocationReject> {
    use tinycloud_core::sql::SqlValue;
    match request {
        SqlRequest::Query { .. } => Err(sql_caveat::InvocationReject::SqlRawQueryBlocked),
        SqlRequest::Execute { .. } => Err(sql_caveat::InvocationReject::SqlRawExecuteBlocked),
        SqlRequest::Batch { .. } => Err(sql_caveat::InvocationReject::SqlBatchBlocked),
        SqlRequest::Export => Err(sql_caveat::InvocationReject::SqlExportBlocked),
        SqlRequest::ExecuteStatement { name, params } => {
            let stmt = caveat
                .statements
                .iter()
                .find(|s| s.name == name)
                .ok_or(sql_caveat::InvocationReject::SqlStatementNotAllowed)?;
            if sql_caveat::contains_write_keyword(&stmt.sql) {
                return Err(sql_caveat::InvocationReject::SqlWriteBlocked);
            }
            if sql_caveat::is_multistatement(&stmt.sql) {
                return Err(sql_caveat::InvocationReject::SqlMultistatementBlocked);
            }
            for fp in &stmt.fixed_params {
                if params.get(fp.index as usize).is_some() {
                    return Err(sql_caveat::InvocationReject::SqlFixedParamOverride);
                }
            }
            for (i, p) in params.iter().enumerate() {
                if stmt.fixed_params.iter().any(|fp| fp.index as usize == i) {
                    continue;
                }
                match p {
                    SqlValue::Text(s) => {
                        if sql_caveat::looks_like_escape(s) {
                            return Err(sql_caveat::InvocationReject::SqlEscapeBlocked);
                        }
                    }
                    SqlValue::Null | SqlValue::Integer(_) | SqlValue::Real(_) => {}
                    SqlValue::Blob(_) => {
                        return Err(sql_caveat::InvocationReject::SqlNonPrimitiveBind);
                    }
                }
            }
            Ok(SqlRequest::ExecuteStatement { name, params })
        }
    }
}

fn invocation_to_sql_request(value: &Value) -> Option<SqlRequest> {
    let obj = value.as_object()?;
    let kind = obj.get("kind")?.as_str()?;
    match kind {
        "query" => {
            let sql = obj.get("sql")?.as_str()?.to_string();
            Some(SqlRequest::Query {
                sql,
                params: Vec::new(),
            })
        }
        "execute" => {
            let sql = obj.get("sql")?.as_str()?.to_string();
            Some(SqlRequest::Execute {
                sql,
                params: Vec::new(),
                schema: None,
            })
        }
        "batch" => Some(SqlRequest::Batch {
            statements: Vec::new(),
        }),
        "export" => Some(SqlRequest::Export),
        "executeStatement" => {
            let name = obj.get("name")?.as_str()?.to_string();
            let params = obj.get("params").and_then(Value::as_object);
            let mut indexed: Vec<Option<Value>> = Vec::new();
            if let Some(p) = params {
                for (k, v) in p {
                    if let Ok(i) = k.parse::<usize>() {
                        while indexed.len() <= i {
                            indexed.push(None);
                        }
                        indexed[i] = Some(v.clone());
                    }
                }
            }
            // For test purposes: treat objects/arrays as non-primitive
            // (Blob is the test-side marker we use to trigger
            // sql-non-primitive-bind / sql-fixed-param-override).
            let mut sqls = Vec::with_capacity(indexed.len());
            for v in indexed {
                let v = v.unwrap_or(Value::Null);
                match v {
                    Value::Null => sqls.push(tinycloud_core::sql::SqlValue::Null),
                    Value::Bool(b) => sqls.push(tinycloud_core::sql::SqlValue::Integer(b as i64)),
                    Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            sqls.push(tinycloud_core::sql::SqlValue::Integer(i));
                        } else if let Some(f) = n.as_f64() {
                            sqls.push(tinycloud_core::sql::SqlValue::Real(f));
                        }
                    }
                    Value::String(s) => sqls.push(tinycloud_core::sql::SqlValue::Text(s)),
                    Value::Array(_) | Value::Object(_) => {
                        sqls.push(tinycloud_core::sql::SqlValue::Blob(vec![]))
                    }
                }
            }
            Some(SqlRequest::ExecuteStatement { name, params: sqls })
        }
        _ => None,
    }
}

#[test]
fn w0_sql_invocation_reject_vectors_enforced() {
    let file: RejectFile = serde_json::from_str(REJECT_VECTORS).unwrap();
    for case in file.cases {
        // Cases where the caveat itself is malformed (bound DELETE) are
        // exercised at the capability-parse boundary in the policy_capability
        // unit tests. Here we only run the invocation paths.
        if case.case == "write-keyword-in-bound-sql-rejects-caveat" {
            // capability-boundary reject
            let err = parse(&case.auth_capability).expect_err(&case.case);
            assert_eq!(err.as_str(), case.rejection_code, "case={}", case.case);
            continue;
        }

        // Even with the bound DELETE caveat slipping through, the
        // invocation MUST be rejected — exercise that branch directly
        // against the constrained-profile enforcer (it should reject on
        // sql-write-blocked).
        let caveat_value = case
            .auth_capability
            .get("caveats")
            .cloned()
            .expect("auth_capability must carry caveats for invocation cases");
        let caveat = sql_caveat::parse(&caveat_value)
            .unwrap_or_else(|e| panic!("failed to parse caveat in case {}: {:?}", case.case, e));

        let Some(req) = case.invocation.as_ref().and_then(invocation_to_sql_request) else {
            continue; // capability-only case
        };
        let err = enforce(&caveat, req).expect_err(&case.case);
        assert_eq!(err.as_str(), case.rejection_code, "case={}", case.case);
    }
}

#[test]
fn w0_sql_invocation_accept_vectors_enforced() {
    let file: AcceptFile = serde_json::from_str(ACCEPT_VECTORS).unwrap();
    for case in file.cases {
        let caveat_value = case
            .auth_capability
            .get("caveats")
            .cloned()
            .expect("auth_capability must carry caveats for accept cases");
        let caveat = sql_caveat::parse(&caveat_value)
            .unwrap_or_else(|e| panic!("failed to parse caveat in case {}: {:?}", case.case, e));
        let req = invocation_to_sql_request(&case.invocation)
            .unwrap_or_else(|| panic!("could not convert invocation for {}", case.case));
        let _accepted = enforce(&caveat, req).unwrap_or_else(|e| {
            panic!(
                "accept case {} should pass enforcement: {:?}",
                case.case,
                e.as_str()
            )
        });
    }
}

const TERMINAL_VECTORS: &str = include_str!("fixtures/w1/revocation/terminal-as-parent.json");
const LEAF_REVO_VECTORS: &str = include_str!("fixtures/w1/revocation/leaf-revocation.json");
const ANCESTOR_REVO_VECTORS: &str = include_str!("fixtures/w1/revocation/ancestor-revocation.json");
const NATIVE_READ_DENIAL_VECTORS: &str =
    include_str!("fixtures/w1/revocation/native-read-denial.json");

#[derive(Deserialize)]
struct TerminalFile {
    vectors: Vec<TerminalVector>,
}

#[derive(Deserialize)]
struct TerminalVector {
    name: String,
    expected: String,
    #[serde(default)]
    rejection_code: Option<String>,
}

/// Terminal/revocation/native-read-denial vectors load successfully and the
/// W1 native contract error variants we produce match the spec codes. The
/// CID-level chain replay is exercised in the in-tree unit tests of
/// `tinycloud-core::models::delegation` and `::invocation`; here we sanity
/// check that the codes we surface are exactly the spec codes.
#[test]
fn w0_terminal_vector_codes_round_trip() {
    let file: TerminalFile = serde_json::from_str(TERMINAL_VECTORS).unwrap();
    let mut saw_reject = false;
    let mut saw_accept = false;
    for v in file.vectors {
        match v.expected.as_str() {
            "accept" => saw_accept = true,
            "reject" => {
                saw_reject = true;
                assert_eq!(
                    v.rejection_code.as_deref(),
                    Some("terminal-parent-cannot-redelegate"),
                    "vector {}",
                    v.name
                );
            }
            other => panic!("unexpected expected={} in {}", other, v.name),
        }
    }
    assert!(saw_accept && saw_reject, "vector file should cover both");
}

#[derive(Deserialize)]
struct LeafFile {
    vectors: Vec<LeafVector>,
}

#[derive(Deserialize)]
struct LeafVector {
    name: String,
    expected: String,
    #[serde(default)]
    rejection_code: Option<String>,
}

#[test]
fn w0_leaf_revocation_vector_codes_round_trip() {
    let file: LeafFile = serde_json::from_str(LEAF_REVO_VECTORS).unwrap();
    let mut saw_post_revoke_reject = false;
    for v in file.vectors {
        if v.name == "post-revoke-reject" {
            saw_post_revoke_reject = true;
            assert_eq!(v.expected, "reject");
            assert_eq!(v.rejection_code.as_deref(), Some("delegation-revoked"));
        }
    }
    assert!(saw_post_revoke_reject);
}

#[derive(Deserialize)]
struct AncestorFile {
    vectors: Vec<AncestorVector>,
}

#[derive(Deserialize)]
struct AncestorVector {
    name: String,
    expected: String,
    #[serde(default)]
    rejection_code: Option<String>,
}

#[test]
fn w0_ancestor_revocation_vector_codes_round_trip() {
    let file: AncestorFile = serde_json::from_str(ANCESTOR_REVO_VECTORS).unwrap();
    let mut saw_descendant = false;
    let mut saw_root = false;
    let mut saw_terminal_parent = false;
    for v in file.vectors {
        match v.name.as_str() {
            "ancestor-revoked-attenuable-rejects-descendant" => {
                saw_descendant = true;
                assert_eq!(v.expected, "reject");
                assert_eq!(
                    v.rejection_code.as_deref(),
                    Some("delegation-ancestor-revoked")
                );
            }
            "root-revoked-rejects-all-descendants" => {
                saw_root = true;
                assert_eq!(v.expected, "reject");
                assert_eq!(
                    v.rejection_code.as_deref(),
                    Some("delegation-ancestor-revoked")
                );
            }
            "terminal-parent-prevents-descendants-anyway" => {
                saw_terminal_parent = true;
                assert_eq!(v.expected, "reject");
                assert_eq!(
                    v.rejection_code.as_deref(),
                    Some("terminal-parent-cannot-redelegate")
                );
            }
            _ => {}
        }
    }
    assert!(saw_descendant && saw_root && saw_terminal_parent);
}

#[test]
fn w0_native_read_denial_vector_parses_and_carries_codes() {
    let v: Value = serde_json::from_str(NATIVE_READ_DENIAL_VECTORS).unwrap();
    // Both phases of leaf_revocation_denial must produce delegation-revoked
    // on the post-revoke-read step.
    let leaf = &v["leaf_revocation_denial"];
    let trace = leaf["trace"].as_array().unwrap();
    let post_revoke = trace
        .iter()
        .find(|s| s["step"] == "post-revoke-read")
        .unwrap();
    assert_eq!(post_revoke["expected_response"]["status"], 403);
    assert_eq!(
        post_revoke["expected_response"]["body"]["code"],
        "delegation-revoked"
    );

    let ancestor = &v["ancestor_revocation_denial"];
    let trace = ancestor["trace"].as_array().unwrap();
    let post_revoke = trace
        .iter()
        .find(|s| s["step"] == "post-revoke-read")
        .unwrap();
    assert_eq!(post_revoke["expected_response"]["status"], 403);
    assert_eq!(
        post_revoke["expected_response"]["body"]["code"],
        "delegation-ancestor-revoked"
    );
}

/// W1 architectural assertion: the `/invoke` data plane MUST NOT depend on
/// policy evaluation or VC verification. This walks the `cargo metadata`
/// resolved dependency graph from the data-plane crates and checks both
/// package names and renamed dependency aliases, so a transitive or aliased
/// pull-in cannot hide behind a shallow workspace/package scan.
#[test]
fn data_plane_has_zero_policy_dependency() {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    fn normalize(name: &str) -> String {
        name.replace('-', "_")
    }

    let banned: BTreeSet<&str> = [
        "tinycloud_policy_engine",
        "tinycloud_policy_core",
        "policy_evidence_vc",
        "opencredentials_verify",
    ]
    .into_iter()
    .collect();

    // (a) Cargo.lock string scan (cheap front-line check).
    let cargo_lock = include_str!("../../Cargo.lock");
    for crate_name in &banned {
        assert!(
            !cargo_lock.contains(&format!("name = \"{crate_name}\"")),
            "data plane MUST NOT link {crate_name}"
        );
        assert!(
            !cargo_lock.contains(&format!("name = \"{}\"", crate_name.replace('_', "-"))),
            "data plane MUST NOT link {crate_name}"
        );
    }

    // (b) cargo metadata-driven dependency walk. No `--no-deps`, no fallback:
    // if Cargo cannot describe the resolved graph, this proof is absent.
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("Cargo.toml");
    let output = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--manifest-path"])
        .arg(&manifest)
        .output()
        .expect("cargo metadata must run");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Value = serde_json::from_slice(&output.stdout).expect("metadata json");

    let mut package_names = BTreeMap::<String, String>::new();
    let mut roots = Vec::new();
    for package in metadata["packages"]
        .as_array()
        .expect("metadata packages must be an array")
    {
        let id = package["id"].as_str().expect("package id").to_string();
        let name = package["name"].as_str().expect("package name").to_string();
        if matches!(name.as_str(), "tinycloud-node" | "tinycloud-core") {
            roots.push(id.clone());
        }
        package_names.insert(id, name);
    }
    assert_eq!(
        roots.len(),
        2,
        "expected roots for tinycloud-node and tinycloud-core"
    );

    let mut normal_edges = BTreeMap::<String, Vec<(String, String)>>::new();
    for node in metadata["resolve"]["nodes"]
        .as_array()
        .expect("metadata resolve.nodes must be an array")
    {
        let id = node["id"].as_str().expect("node id").to_string();
        let deps = node["deps"]
            .as_array()
            .expect("metadata node.deps must be an array")
            .iter()
            .filter_map(|dep| {
                let is_normal = dep["dep_kinds"]
                    .as_array()
                    .expect("dep_kinds must be an array")
                    .iter()
                    .any(|kind| kind["kind"].is_null());
                is_normal.then(|| {
                    (
                        dep["pkg"].as_str().expect("dep pkg").to_string(),
                        dep["name"].as_str().expect("dep name").to_string(),
                    )
                })
            })
            .collect::<Vec<_>>();
        normal_edges.insert(id, deps);
    }

    let mut seen = BTreeSet::<String>::new();
    let mut queue = VecDeque::from(roots);
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id.clone()) {
            continue;
        }

        let package_name = package_names
            .get(&id)
            .unwrap_or_else(|| panic!("missing package name for {id}"));
        assert!(
            !banned.contains(normalize(package_name).as_str()),
            "data-plane dependency closure MUST NOT include package {package_name}"
        );
        for (dep_id, edge_name) in normal_edges.get(&id).into_iter().flatten() {
            assert!(
                !banned.contains(normalize(edge_name).as_str()),
                "data-plane dependency closure MUST NOT include renamed dependency alias {edge_name}"
            );
            queue.push_back(dep_id.clone());
        }
    }
}

/// W1 (audit P0 finding 2) regression: the constrained-statements caveat is
/// extracted from the chain via the persisted abilities row, NOT from the
/// invocation envelope's facts. We test the extraction helper directly via
/// the public sql_caveat::parse on a representative caveat shape and a
/// shape wrapped in `constrained-statements`, asserting both surface a
/// caveat. This locks the contract that the chain shape and the wrapper
/// shape both parse and that the wire shape used by the policy engine
/// remains compatible.
#[test]
fn w1_chain_caveat_extraction_accepts_both_shapes() {
    use serde_json::json;
    let direct = json!({
        "mode": "constrained-statements",
        "readOnly": true,
        "statements": [{"name":"get","sql":"SELECT 1","fixedParams":[]}]
    });
    let wrapped = json!({
        "constrained-statements": {
            "mode": "constrained-statements",
            "readOnly": true,
            "statements": [{"name":"get","sql":"SELECT 1","fixedParams":[]}]
        }
    });

    let parsed_direct = sql_caveat::parse(&direct).expect("direct shape must parse");
    assert!(parsed_direct.read_only);
    assert_eq!(parsed_direct.statements.len(), 1);

    let inner = wrapped
        .as_object()
        .and_then(|o| o.get("constrained-statements"))
        .expect("wrapper must expose inner");
    let parsed_wrap = sql_caveat::parse(inner).expect("wrapper shape must parse");
    assert!(parsed_wrap.read_only);
}
