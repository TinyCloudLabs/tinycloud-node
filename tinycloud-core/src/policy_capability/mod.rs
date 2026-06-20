// Native authority-contract types for TinyCloud credential-gated delegation v0.
//
// This module is the on-node side of the W0 frozen contracts in
// `policy-engine/spec/policy-capability.md` and
// `policy-engine/spec/sql-constrained-statement-caveat.md`.
//
// It defines:
//   * `PolicyCapability` — the resolved authority shape (NOT a manifest payload)
//   * JCS canonicalization + the domain-separated SHA-256 capability hash
//   * Containment (subset) checks, including service/space/path/actions/caveats
//   * `SqlConstrainedStatementCaveat` and containment for it
//
// Crucially, this module has ZERO dependency on policy evaluation or VC
// verification — it is the native contract types only.

pub mod jcs;
pub mod sql_caveat;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub use sql_caveat::SqlConstrainedStatementCaveat;

/// Domain separator for `PolicyCapability` hashing. The trailing NUL byte
/// (0x00) is part of the hash input — do not strip it.
pub const POLICY_CAPABILITY_DOMAIN: &[u8] = b"xyz.tinycloud.policy/PolicyCapability/v0\0";

/// The v0 accepted action set per service. See policy-capability.md §4.
pub fn accepted_actions(service: &str) -> Option<&'static [&'static str]> {
    match service {
        "tinycloud.kv" => Some(&[
            "tinycloud.kv/get",
            "tinycloud.kv/list",
            "tinycloud.kv/metadata",
            "tinycloud.kv/put",
            "tinycloud.kv/delete",
        ]),
        "tinycloud.sql" => Some(&[
            "tinycloud.sql/read",
            "tinycloud.sql/select",
            "tinycloud.sql/write",
        ]),
        "tinycloud.vfs" => Some(&[
            "tinycloud.vfs/get",
            "tinycloud.vfs/list",
            "tinycloud.vfs/metadata",
            "tinycloud.vfs/put",
            "tinycloud.vfs/delete",
        ]),
        _ => None,
    }
}

/// PolicyCapability — resolved authority shape used by ceilings, requested
/// capabilities, delegation expansion, and grant issuance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyCapability {
    pub service: String,
    pub space: String,
    pub path: String,
    /// Sorted, deduped, normalized full action URNs.
    pub actions: Vec<String>,
    /// Optional service-native caveats — already JCS-canonical.
    pub caveats: Option<Value>,
}

/// Boundary-rejection codes per policy-capability.md §2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectionCode {
    PolicyCapabilityMalformedService,
    PolicyCapabilityMalformedSpace,
    PolicyCapabilityMalformedPath,
    PolicyCapabilityMalformedActionShortname,
    PolicyCapabilityMalformedAction,
    PolicyCapabilityEmptyActions,
    PolicyCapabilityMalformedCaveats,
    PolicyCapabilityUnknownKey,
    PolicyCapabilityMalformed,
    ContainmentServiceMismatch,
    ContainmentSpaceMismatch,
    ContainmentPathMismatch,
    ContainmentActionNotSubset,
    ContainmentCaveatRequired,
    ContainmentSqlFixedParamDropped,
    ContainmentSqlFixedParamMismatch,
    ContainmentSqlStatementAdded,
    SqlNonReadonlyNotPermitted,
    SqlWriteBlocked,
}

impl RejectionCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PolicyCapabilityMalformedService => "policy-capability-malformed-service",
            Self::PolicyCapabilityMalformedSpace => "policy-capability-malformed-space",
            Self::PolicyCapabilityMalformedPath => "policy-capability-malformed-path",
            Self::PolicyCapabilityMalformedActionShortname => {
                "policy-capability-malformed-action-shortname"
            }
            Self::PolicyCapabilityMalformedAction => "policy-capability-malformed-action",
            Self::PolicyCapabilityEmptyActions => "policy-capability-empty-actions",
            Self::PolicyCapabilityMalformedCaveats => "policy-capability-malformed-caveats",
            Self::PolicyCapabilityUnknownKey => "policy-capability-unknown-key",
            Self::PolicyCapabilityMalformed => "policy-capability-malformed",
            Self::ContainmentServiceMismatch => "containment-service-mismatch",
            Self::ContainmentSpaceMismatch => "containment-space-mismatch",
            Self::ContainmentPathMismatch => "containment-path-mismatch",
            Self::ContainmentActionNotSubset => "containment-action-not-subset",
            Self::ContainmentCaveatRequired => "containment-caveat-required",
            Self::ContainmentSqlFixedParamDropped => "containment-sql-fixed-param-dropped",
            Self::ContainmentSqlFixedParamMismatch => "containment-sql-fixed-param-mismatch",
            Self::ContainmentSqlStatementAdded => "containment-sql-statement-added",
            Self::SqlNonReadonlyNotPermitted => "sql-non-readonly-not-permitted",
            Self::SqlWriteBlocked => "sql-write-blocked",
        }
    }
}

/// Known top-level keys in a PolicyCapability payload (unknown keys are a
/// boundary error).
const ALLOWED_KEYS: &[&str] = &["service", "space", "path", "actions", "caveats"];

/// Manifest-shaped marker keys — presence of any of these is a rejection.
const MANIFEST_MARKER_KEYS: &[&str] = &["id", "scope", "type", "actions_short", "permissions"];

/// Parse a raw JSON value into a validated, normalized `PolicyCapability`.
/// Runs boundary checks (§2 of policy-capability.md) BEFORE normalization or
/// hashing. Returns the post-normalization `PolicyCapability` on success.
pub fn parse(input: &Value) -> Result<PolicyCapability, RejectionCode> {
    let obj = input
        .as_object()
        .ok_or(RejectionCode::PolicyCapabilityMalformed)?;

    // Unknown top-level keys / manifest-shaped detection
    for k in obj.keys() {
        if MANIFEST_MARKER_KEYS.iter().any(|m| m == k) {
            return Err(RejectionCode::PolicyCapabilityMalformed);
        }
        if !ALLOWED_KEYS.iter().any(|a| a == k) {
            return Err(RejectionCode::PolicyCapabilityUnknownKey);
        }
    }

    let service = obj
        .get("service")
        .and_then(Value::as_str)
        .ok_or(RejectionCode::PolicyCapabilityMalformedService)?;
    if service.is_empty() || service.chars().any(char::is_whitespace) {
        return Err(RejectionCode::PolicyCapabilityMalformedService);
    }
    if accepted_actions(service).is_none() {
        return Err(RejectionCode::PolicyCapabilityMalformedService);
    }

    let space = obj
        .get("space")
        .and_then(Value::as_str)
        .ok_or(RejectionCode::PolicyCapabilityMalformedSpace)?;
    if space.is_empty()
        || space.contains('*')
        || space.contains('?')
        || space.starts_with("manifest:")
    {
        return Err(RejectionCode::PolicyCapabilityMalformedSpace);
    }

    let raw_path = obj
        .get("path")
        .and_then(Value::as_str)
        .ok_or(RejectionCode::PolicyCapabilityMalformedPath)?;
    let path = normalize_path(service, raw_path)?;

    let actions_value = obj
        .get("actions")
        .ok_or(RejectionCode::PolicyCapabilityEmptyActions)?;
    let actions_arr = actions_value
        .as_array()
        .ok_or(RejectionCode::PolicyCapabilityMalformedAction)?;
    let accepted = accepted_actions(service).expect("service was validated");

    let mut actions: Vec<String> = Vec::with_capacity(actions_arr.len());
    for a in actions_arr {
        let s = a
            .as_str()
            .ok_or(RejectionCode::PolicyCapabilityMalformedAction)?;
        // Short-name detection: any action without a "<service>/" prefix is a
        // shortname. Also catches well-known aliases like "*", "read".
        if !s.contains('/') {
            return Err(RejectionCode::PolicyCapabilityMalformedActionShortname);
        }
        if !accepted.iter().any(|x| *x == s) {
            return Err(RejectionCode::PolicyCapabilityMalformedAction);
        }
        actions.push(s.to_string());
    }
    actions.sort();
    actions.dedup();
    if actions.is_empty() {
        return Err(RejectionCode::PolicyCapabilityEmptyActions);
    }

    let caveats = match obj.get("caveats") {
        None => None,
        Some(v) => {
            // Must be a JSON object (anything else is malformed for v0 services).
            if !v.is_object() {
                return Err(RejectionCode::PolicyCapabilityMalformedCaveats);
            }
            // SQL caveats get a stricter shape check + bound-SQL safety check.
            if service == "tinycloud.sql" {
                let caveat = sql_caveat::parse(v)?;
                // Action containment for the SQL profile: §2 of
                // sql-constrained-statement-caveat.md.
                for a in &actions {
                    if a != "tinycloud.sql/read" && a != "tinycloud.sql/select" {
                        return Err(RejectionCode::PolicyCapabilityMalformed);
                    }
                }
                // Bound SQL write-keyword check.
                for stmt in &caveat.statements {
                    if sql_caveat::contains_write_keyword(&stmt.sql) {
                        return Err(RejectionCode::SqlWriteBlocked);
                    }
                }
            }
            Some(v.clone())
        }
    };

    Ok(PolicyCapability {
        service: service.to_string(),
        space: space.to_string(),
        path,
        actions,
        caveats,
    })
}

/// Service-specific path normalization. Implements the rules in §3 of
/// policy-capability.md: NFC, percent-decode unreserved, reject `..`.
pub fn normalize_path(service: &str, path: &str) -> Result<String, RejectionCode> {
    // Percent-decode unreserved characters (RFC 3986).
    let decoded = percent_decode_unreserved(path);
    // NFC normalize.
    let nfc: String = unicode_normalize_nfc(&decoded);
    // Reject `..` path segments outright (no rewriting).
    for seg in nfc.split('/') {
        if seg == ".." {
            return Err(RejectionCode::PolicyCapabilityMalformedPath);
        }
    }
    // Service-specific: SQL paths must be a concrete db path/name (no table
    // expression). We allow any non-empty path with no '..' here; the deeper
    // schema-mismatch check is the SQL service's job at invocation time.
    if service == "tinycloud.sql" && nfc.is_empty() {
        return Err(RejectionCode::PolicyCapabilityMalformedPath);
    }
    Ok(nfc)
}

fn percent_decode_unreserved(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' && i + 2 < chars.len() {
            let hi = chars[i + 1].to_digit(16).and_then(|d| u8::try_from(d).ok());
            let lo = chars[i + 2].to_digit(16).and_then(|d| u8::try_from(d).ok());
            if let (Some(hi), Some(lo)) = (hi, lo) {
                let c = (hi << 4) | lo;
                // Unreserved per RFC 3986: ALPHA / DIGIT / - / . / _ / ~
                let is_unreserved = c.is_ascii_alphanumeric()
                    || c == b'-'
                    || c == b'.'
                    || c == b'_'
                    || c == b'~';
                if is_unreserved {
                    out.push(c as char);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Full Unicode NFC normalization (W1 audit P1). Delegates to
/// `unicode-normalization`, which implements UAX #15 — the prior hand-coded
/// subset only covered a narrow precomposed-pair table and could not
/// canonicalize arbitrary base+combining sequences. We want path
/// canonicalization to be spec-sound; this also makes the JCS caveat-side
/// containment robust against attacker-supplied glyph alternates.
fn unicode_normalize_nfc(s: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    s.nfc().collect()
}

impl PolicyCapability {
    /// JCS-canonical UTF-8 bytes of the capability (sorted keys, no whitespace).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut map = serde_json::Map::new();
        map.insert(
            "actions".to_string(),
            Value::Array(
                self.actions
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        if let Some(c) = &self.caveats {
            map.insert("caveats".to_string(), c.clone());
        }
        map.insert("path".to_string(), Value::String(self.path.clone()));
        map.insert("service".to_string(), Value::String(self.service.clone()));
        map.insert("space".to_string(), Value::String(self.space.clone()));
        jcs::canonicalize(&Value::Object(map))
    }

    /// Bare lowercase hex of SHA-256(domain || canonical_bytes).
    pub fn capability_hash_hex(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(POLICY_CAPABILITY_DOMAIN);
        hasher.update(self.canonical_bytes());
        let digest = hasher.finalize();
        hex_encode(&digest)
    }

    /// Containment check: `req ⊑ self` per §7 of policy-capability.md.
    pub fn contains(&self, req: &PolicyCapability) -> Result<(), RejectionCode> {
        if self.service != req.service {
            return Err(RejectionCode::ContainmentServiceMismatch);
        }
        if self.space != req.space {
            return Err(RejectionCode::ContainmentSpaceMismatch);
        }
        if !path_contains(&self.service, &self.path, &req.path) {
            return Err(RejectionCode::ContainmentPathMismatch);
        }
        for a in &req.actions {
            if !self.actions.iter().any(|x| x == a) {
                return Err(RejectionCode::ContainmentActionNotSubset);
            }
        }
        match (&self.caveats, &req.caveats) {
            (None, _) => {}
            (Some(_), None) => return Err(RejectionCode::ContainmentCaveatRequired),
            (Some(auth_c), Some(req_c)) => {
                if self.service == "tinycloud.sql" {
                    let auth = sql_caveat::parse(auth_c)?;
                    let req = sql_caveat::parse(req_c)?;
                    sql_caveat::contains(&auth, &req)?;
                }
            }
        }
        Ok(())
    }
}

/// Path containment per service. For KV/VFS, a trailing-slash auth.path is a
/// prefix that must end on a path-component boundary. Without trailing slash
/// the match is exact. For SQL, exact match only.
pub fn path_contains(service: &str, auth: &str, req: &str) -> bool {
    match service {
        "tinycloud.sql" => auth == req,
        _ => {
            if auth == req {
                return true;
            }
            if auth.ends_with('/') {
                // Prefix-with-slash: req must extend the prefix on a
                // component boundary. "docs/" matches itself and any
                // strict descendant; "docs" (no trailing slash) does not.
                if let Some(rest) = req.strip_prefix(auth) {
                    return !rest.is_empty();
                }
                false
            } else {
                // Exact key authority — only matches itself exactly.
                false
            }
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Public re-export for downstream code that needs the canonical hash for a
/// (resource, ability) pair without owning a full `PolicyCapability` —
/// constructed lazily for chain checks.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResolvedAuthority {
    pub service: String,
    pub space: String,
    pub path: String,
    pub action: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANON_VECTORS: &str = include_str!(
        "../../../../policy-engine/test-vectors/policy-capability/canonicalization-vectors.json"
    );
    const CONTAINMENT_VECTORS: &str = include_str!(
        "../../../../policy-engine/test-vectors/policy-capability/containment-vectors.json"
    );
    const REJECTION_VECTORS: &str = include_str!(
        "../../../../policy-engine/test-vectors/policy-capability/rejection-vectors.json"
    );
    const SQL_CONTAINMENT_VECTORS: &str =
        include_str!("../../../../policy-engine/test-vectors/sql-caveat/containment.json");
    const SQL_REJECT_VECTORS: &str =
        include_str!("../../../../policy-engine/test-vectors/sql-caveat/reject.json");

    #[derive(Deserialize)]
    struct CanonVector {
        name: String,
        input: Value,
        canonical_jcs_utf8_hex: String,
        policy_capability_hash_hex: String,
    }

    #[derive(Deserialize)]
    struct CanonFile {
        vectors: Vec<CanonVector>,
    }

    #[test]
    fn w0_capability_canonicalization_and_hash_match() {
        let file: CanonFile = serde_json::from_str(CANON_VECTORS).unwrap();
        for v in file.vectors {
            let parsed = parse(&v.input).unwrap_or_else(|e| {
                panic!("vector {} should parse but rejected: {:?}", v.name, e)
            });
            let canon = parsed.canonical_bytes();
            assert_eq!(
                hex_encode(&canon),
                v.canonical_jcs_utf8_hex,
                "canonical bytes mismatch for {}",
                v.name
            );
            assert_eq!(
                parsed.capability_hash_hex(),
                v.policy_capability_hash_hex,
                "hash mismatch for {}",
                v.name
            );
        }
    }

    #[derive(Deserialize)]
    struct ContainVector {
        name: String,
        auth: Value,
        req: Value,
        contained: bool,
        #[serde(default)]
        rejection_code: Option<String>,
    }

    #[derive(Deserialize)]
    struct ContainFile {
        vectors: Vec<ContainVector>,
    }

    #[test]
    fn w0_capability_containment_matches() {
        let file: ContainFile = serde_json::from_str(CONTAINMENT_VECTORS).unwrap();
        for v in file.vectors {
            let auth = parse(&v.auth);
            let req = parse(&v.req);
            match (auth, req, v.contained) {
                (Ok(a), Ok(r), true) => {
                    a.contains(&r)
                        .unwrap_or_else(|e| panic!("{} should be contained: {:?}", v.name, e));
                }
                (Ok(a), Ok(r), false) => {
                    let err = a.contains(&r).expect_err(&format!(
                        "{} should NOT be contained but was",
                        v.name
                    ));
                    if let Some(code) = v.rejection_code {
                        assert_eq!(err.as_str(), code, "code mismatch for {}", v.name);
                    }
                }
                (Err(e), _, false) | (_, Err(e), false) => {
                    // Boundary-rejected payloads are trivially "not contained";
                    // only assert the code when the vector's expected code is
                    // itself a boundary code (rather than a containment code).
                    if let Some(code) = v.rejection_code {
                        if code.starts_with("policy-capability-") {
                            assert_eq!(e.as_str(), code, "parse code mismatch for {}", v.name);
                        }
                    }
                }
                (a, r, c) => panic!(
                    "unexpected combo for {}: auth={:?}, req={:?}, contained={}",
                    v.name, a, r, c
                ),
            }
        }
    }

    #[derive(Deserialize)]
    struct RejectionVector {
        name: String,
        rejection_code: String,
        input: Value,
    }

    #[derive(Deserialize)]
    struct RejectionFile {
        vectors: Vec<RejectionVector>,
    }

    #[test]
    fn w0_capability_rejections_match_codes() {
        let file: RejectionFile = serde_json::from_str(REJECTION_VECTORS).unwrap();
        for v in file.vectors {
            let err = parse(&v.input)
                .expect_err(&format!("vector {} must be rejected", v.name));
            assert_eq!(
                err.as_str(),
                v.rejection_code,
                "rejection code mismatch for {}",
                v.name
            );
        }
    }

    #[derive(Deserialize)]
    struct SqlContainVector {
        name: String,
        auth_caveat: Value,
        req_caveat: Value,
        contained: bool,
        #[serde(default)]
        rejection_code: Option<String>,
    }

    #[derive(Deserialize)]
    struct SqlContainFile {
        vectors: Vec<SqlContainVector>,
    }

    #[test]
    fn w0_sql_caveat_containment_matches() {
        let file: SqlContainFile = serde_json::from_str(SQL_CONTAINMENT_VECTORS).unwrap();
        for v in file.vectors {
            let auth = sql_caveat::parse(&v.auth_caveat);
            let req = sql_caveat::parse(&v.req_caveat);
            match (auth, req, v.contained) {
                (Ok(a), Ok(r), true) => {
                    sql_caveat::contains(&a, &r)
                        .unwrap_or_else(|e| panic!("{} should be contained: {:?}", v.name, e));
                }
                (Ok(a), Ok(r), false) => {
                    let err = sql_caveat::contains(&a, &r).expect_err(&format!(
                        "{} should NOT be contained",
                        v.name
                    ));
                    if let Some(code) = v.rejection_code {
                        assert_eq!(err.as_str(), code, "code mismatch for {}", v.name);
                    }
                }
                (Err(e), _, false) | (_, Err(e), false) => {
                    if let Some(code) = v.rejection_code {
                        assert_eq!(e.as_str(), code, "parse-code mismatch for {}", v.name);
                    }
                }
                (a, r, c) => panic!(
                    "unexpected combo for {}: auth={:?}, req={:?}, contained={}",
                    v.name, a, r, c
                ),
            }
        }
    }

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct SqlRejectCase {
        case: String,
        auth_capability: Value,
        #[serde(default)]
        invocation: Option<Value>,
        rejection_code: String,
    }

    #[derive(Deserialize)]
    struct SqlRejectFile {
        cases: Vec<SqlRejectCase>,
    }

    #[test]
    fn w0_sql_reject_cases_covered_at_least_at_capability_boundary() {
        // Confirm the capability-level rejections (write-keyword in bound SQL)
        // are caught by `parse(...)` boundary check. Invocation-time SQL
        // enforcement is verified separately in the SQL service tests.
        let file: SqlRejectFile = serde_json::from_str(SQL_REJECT_VECTORS).unwrap();
        for case in file.cases {
            if case.case.contains("write-keyword-in-bound-sql-rejects-caveat") {
                let err = parse(&case.auth_capability).expect_err(&case.case);
                assert_eq!(err.as_str(), "sql-write-blocked");
            }
        }
    }
}
