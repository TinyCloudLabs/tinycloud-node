use crate::jcs;
use crate::sql_caveat;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use unicode_normalization::UnicodeNormalization;

pub const POLICY_CAPABILITY_DOMAIN: &[u8] = b"xyz.tinycloud.policy/PolicyCapability/v0\0";
pub const REQUESTED_CAPABILITIES_DOMAIN: &[u8] = b"xyz.tinycloud.policy/RequestedCapabilities/v0\0";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityRejection {
    #[error("policy-capability-malformed-service")]
    PolicyCapabilityMalformedService,
    #[error("policy-capability-malformed-space")]
    PolicyCapabilityMalformedSpace,
    #[error("policy-capability-malformed-path")]
    PolicyCapabilityMalformedPath,
    #[error("policy-capability-malformed-action-shortname")]
    PolicyCapabilityMalformedActionShortname,
    #[error("policy-capability-malformed-action")]
    PolicyCapabilityMalformedAction,
    #[error("policy-capability-empty-actions")]
    PolicyCapabilityEmptyActions,
    #[error("policy-capability-malformed-caveats")]
    PolicyCapabilityMalformedCaveats,
    #[error("policy-capability-unknown-key")]
    PolicyCapabilityUnknownKey,
    #[error("policy-capability-malformed")]
    PolicyCapabilityMalformed,
    #[error("containment-service-mismatch")]
    ContainmentServiceMismatch,
    #[error("containment-space-mismatch")]
    ContainmentSpaceMismatch,
    #[error("containment-path-mismatch")]
    ContainmentPathMismatch,
    #[error("containment-action-not-subset")]
    ContainmentActionNotSubset,
    #[error("containment-caveat-required")]
    ContainmentCaveatRequired,
    #[error("containment-sql-fixed-param-dropped")]
    ContainmentSqlFixedParamDropped,
    #[error("containment-sql-fixed-param-mismatch")]
    ContainmentSqlFixedParamMismatch,
    #[error("containment-sql-statement-added")]
    ContainmentSqlStatementAdded,
    #[error("sql-non-readonly-not-permitted")]
    SqlNonReadonlyNotPermitted,
    #[error("sql-write-blocked")]
    SqlWriteBlocked,
}

impl CapabilityRejection {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyCapability {
    pub service: String,
    pub space: String,
    pub path: String,
    pub actions: Vec<String>,
    pub caveats: Option<Value>,
}

impl PolicyCapability {
    pub fn canonical_value(&self) -> Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "actions".to_string(),
            Value::Array(
                self.actions
                    .iter()
                    .map(|action| Value::String(action.clone()))
                    .collect(),
            ),
        );
        if let Some(caveats) = &self.caveats {
            map.insert("caveats".to_string(), caveats.clone());
        }
        map.insert("path".to_string(), Value::String(self.path.clone()));
        map.insert("service".to_string(), Value::String(self.service.clone()));
        map.insert("space".to_string(), Value::String(self.space.clone()));
        Value::Object(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        jcs::canonicalize(&self.canonical_value())
    }

    pub fn capability_hash_hex(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(POLICY_CAPABILITY_DOMAIN);
        hasher.update(self.canonical_bytes());
        hex_lower(&hasher.finalize())
    }

    pub fn contains(&self, req: &PolicyCapability) -> Result<(), CapabilityRejection> {
        if self.service != req.service {
            return Err(CapabilityRejection::ContainmentServiceMismatch);
        }
        if self.space != req.space {
            return Err(CapabilityRejection::ContainmentSpaceMismatch);
        }
        if !path_contains(&self.service, &self.path, &req.path) {
            return Err(CapabilityRejection::ContainmentPathMismatch);
        }
        for action in &req.actions {
            if !self.actions.iter().any(|candidate| candidate == action) {
                return Err(CapabilityRejection::ContainmentActionNotSubset);
            }
        }

        match (&self.caveats, &req.caveats) {
            (None, _) => {}
            (Some(_), None) => return Err(CapabilityRejection::ContainmentCaveatRequired),
            (Some(auth), Some(req)) if self.service == "tinycloud.sql" => {
                let auth = sql_caveat::parse(auth)?;
                let req = sql_caveat::parse(req)?;
                sql_caveat::contains(&auth, &req)?;
            }
            (Some(_), Some(_)) => {}
        }
        Ok(())
    }
}

impl Serialize for PolicyCapability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.canonical_value().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PolicyCapability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        parse_policy_capability(&value).map_err(serde::de::Error::custom)
    }
}

pub fn parse_policy_capability(input: &Value) -> Result<PolicyCapability, CapabilityRejection> {
    const ALLOWED_KEYS: &[&str] = &["service", "space", "path", "actions", "caveats"];
    const MANIFEST_KEYS: &[&str] = &["id", "scope", "type", "actions_short", "permissions"];

    let object = input
        .as_object()
        .ok_or(CapabilityRejection::PolicyCapabilityMalformed)?;
    for key in object.keys() {
        if MANIFEST_KEYS.iter().any(|marker| marker == key) {
            return Err(CapabilityRejection::PolicyCapabilityMalformed);
        }
        if !ALLOWED_KEYS.iter().any(|allowed| allowed == key) {
            return Err(CapabilityRejection::PolicyCapabilityUnknownKey);
        }
    }

    let service = object
        .get("service")
        .and_then(Value::as_str)
        .ok_or(CapabilityRejection::PolicyCapabilityMalformedService)?;
    if service.is_empty()
        || service.chars().any(char::is_whitespace)
        || accepted_actions(service).is_none()
    {
        return Err(CapabilityRejection::PolicyCapabilityMalformedService);
    }

    let space = object
        .get("space")
        .and_then(Value::as_str)
        .ok_or(CapabilityRejection::PolicyCapabilityMalformedSpace)?;
    if space.is_empty()
        || space.contains('*')
        || space.contains('?')
        || space.starts_with("manifest:")
    {
        return Err(CapabilityRejection::PolicyCapabilityMalformedSpace);
    }

    let raw_path = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or(CapabilityRejection::PolicyCapabilityMalformedPath)?;
    let path = normalize_path(service, raw_path)?;

    let actions = object
        .get("actions")
        .and_then(Value::as_array)
        .ok_or(CapabilityRejection::PolicyCapabilityEmptyActions)?;
    let accepted = accepted_actions(service).expect("service already checked");
    let mut normalized_actions = BTreeSet::new();
    for action in actions {
        let action = action
            .as_str()
            .ok_or(CapabilityRejection::PolicyCapabilityMalformedAction)?;
        if !action.contains('/') {
            return Err(CapabilityRejection::PolicyCapabilityMalformedActionShortname);
        }
        if !accepted.contains(&action) {
            return Err(CapabilityRejection::PolicyCapabilityMalformedAction);
        }
        normalized_actions.insert(action.to_string());
    }
    if normalized_actions.is_empty() {
        return Err(CapabilityRejection::PolicyCapabilityEmptyActions);
    }
    let actions: Vec<String> = normalized_actions.into_iter().collect();

    let caveats = match object.get("caveats") {
        None => None,
        Some(caveats) => {
            if !caveats.is_object() {
                return Err(CapabilityRejection::PolicyCapabilityMalformedCaveats);
            }
            if service == "tinycloud.sql" {
                let parsed = sql_caveat::parse(caveats)?;
                if parsed
                    .statements
                    .iter()
                    .any(|statement| sql_caveat::contains_write_keyword(&statement.sql))
                {
                    return Err(CapabilityRejection::SqlWriteBlocked);
                }
            }
            Some(caveats.clone())
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

pub fn requested_capabilities_hash_hex(caps: &[PolicyCapability]) -> String {
    let mut canonical: Vec<_> = caps.iter().map(PolicyCapability::canonical_value).collect();
    canonical.sort_by(|left, right| {
        let key = |value: &Value| {
            let object = value.as_object().expect("capability is object");
            (
                object
                    .get("service")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                object
                    .get("space")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                object
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            )
        };
        key(left).cmp(&key(right))
    });
    let mut hasher = Sha256::new();
    hasher.update(REQUESTED_CAPABILITIES_DOMAIN);
    hasher.update(jcs::canonicalize(&Value::Array(canonical)));
    hex_lower(&hasher.finalize())
}

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

pub fn normalize_path(service: &str, path: &str) -> Result<String, CapabilityRejection> {
    let decoded = percent_decode_unreserved(path);
    let nfc: String = decoded.nfc().collect();
    if nfc.split('/').any(|segment| segment == "..") {
        return Err(CapabilityRejection::PolicyCapabilityMalformedPath);
    }
    if service == "tinycloud.sql" && nfc.is_empty() {
        return Err(CapabilityRejection::PolicyCapabilityMalformedPath);
    }
    Ok(nfc)
}

pub fn path_contains(service: &str, auth: &str, req: &str) -> bool {
    match service {
        "tinycloud.sql" => auth == req,
        _ if auth == req => true,
        _ if auth.ends_with('/') => req
            .strip_prefix(auth)
            .map(|rest| !rest.is_empty())
            .unwrap_or(false),
        _ => false,
    }
}

fn percent_decode_unreserved(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::with_capacity(value.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '%' && index + 2 < chars.len() {
            let hi = chars[index + 1]
                .to_digit(16)
                .and_then(|value| u8::try_from(value).ok());
            let lo = chars[index + 2]
                .to_digit(16)
                .and_then(|value| u8::try_from(value).ok());
            if let (Some(hi), Some(lo)) = (hi, lo) {
                let byte = (hi << 4) | lo;
                if byte.is_ascii_alphanumeric()
                    || byte == b'-'
                    || byte == b'.'
                    || byte == b'_'
                    || byte == b'~'
                {
                    out.push(byte as char);
                    index += 3;
                    continue;
                }
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
