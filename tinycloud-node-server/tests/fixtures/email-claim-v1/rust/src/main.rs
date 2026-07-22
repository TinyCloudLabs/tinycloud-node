use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RejectionStage {
    ContractValidation,
    CredentialHolder,
    CredentialScope,
    CredentialTime,
    CredentialVct,
    CrossArtifactHolder,
    DocumentNameBytes,
    IssuerKey,
    IssuerTrust,
    NodeAuthority,
    NodeEnrollment,
    NodeKeyRetirement,
    NodeKeyRotation,
    ShareUrlFragment,
    ShareUrlFragmentEncoding,
    ShareUrlKey,
    ShareUrlOrigin,
    ShareUrlPort,
    ShareUrlPath,
    ShareUrlQuery,
    ShareUrlScheme,
    ScannerFragmentEncoding,
    SignatureEncoding,
}

impl RejectionStage {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "contract-validation" => Self::ContractValidation,
            "credential-holder" => Self::CredentialHolder,
            "credential-scope" => Self::CredentialScope,
            "credential-time" => Self::CredentialTime,
            "credential-vct" => Self::CredentialVct,
            "cross-artifact-holder" => Self::CrossArtifactHolder,
            "document-name-bytes" => Self::DocumentNameBytes,
            "issuer-key" => Self::IssuerKey,
            "issuer-trust" => Self::IssuerTrust,
            "node-authority" => Self::NodeAuthority,
            "node-enrollment" => Self::NodeEnrollment,
            "node-key-retirement" => Self::NodeKeyRetirement,
            "node-key-rotation" => Self::NodeKeyRotation,
            "share-url-fragment" => Self::ShareUrlFragment,
            "share-url-fragment-encoding" => Self::ShareUrlFragmentEncoding,
            "share-url-key" => Self::ShareUrlKey,
            "share-url-origin" => Self::ShareUrlOrigin,
            "share-url-port" => Self::ShareUrlPort,
            "share-url-path" => Self::ShareUrlPath,
            "share-url-query" => Self::ShareUrlQuery,
            "share-url-scheme" => Self::ShareUrlScheme,
            "scanner-fragment-encoding" => Self::ScannerFragmentEncoding,
            "signature-encoding" => Self::SignatureEncoding,
            _ => return None,
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::ContractValidation => "contract-validation",
            Self::CredentialHolder => "credential-holder",
            Self::CredentialScope => "credential-scope",
            Self::CredentialTime => "credential-time",
            Self::CredentialVct => "credential-vct",
            Self::CrossArtifactHolder => "cross-artifact-holder",
            Self::DocumentNameBytes => "document-name-bytes",
            Self::IssuerKey => "issuer-key",
            Self::IssuerTrust => "issuer-trust",
            Self::NodeAuthority => "node-authority",
            Self::NodeEnrollment => "node-enrollment",
            Self::NodeKeyRetirement => "node-key-retirement",
            Self::NodeKeyRotation => "node-key-rotation",
            Self::ShareUrlFragment => "share-url-fragment",
            Self::ShareUrlFragmentEncoding => "share-url-fragment-encoding",
            Self::ShareUrlKey => "share-url-key",
            Self::ShareUrlOrigin => "share-url-origin",
            Self::ShareUrlPort => "share-url-port",
            Self::ShareUrlPath => "share-url-path",
            Self::ShareUrlQuery => "share-url-query",
            Self::ShareUrlScheme => "share-url-scheme",
            Self::ScannerFragmentEncoding => "scanner-fragment-encoding",
            Self::SignatureEncoding => "signature-encoding",
        }
    }
}

#[derive(Debug)]
struct NegativeRejection {
    stage: RejectionStage,
    detail: String,
}

#[derive(Debug)]
struct CommandRejection {
    name: String,
    detail: String,
}

#[derive(Debug)]
enum CommandExecutionError {
    Rejected(CommandRejection),
    Invalid(String),
}

impl From<String> for CommandExecutionError {
    fn from(detail: String) -> Self {
        Self::Invalid(detail)
    }
}

impl From<&str> for CommandExecutionError {
    fn from(detail: &str) -> Self {
        Self::Invalid(detail.into())
    }
}

fn reject_command(name: &str, detail: &str) -> CommandExecutionError {
    CommandExecutionError::Rejected(CommandRejection {
        name: name.into(),
        detail: detail.into(),
    })
}

const CONTRACT_VERSION: &str = "tinycloud.share-email-claim/v1";

fn exact_object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
    label: &str,
) -> Result<&'a Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label}: object required"))?;
    for key in required {
        assert_ok(
            object.contains_key(*key),
            &format!("{label}: missing {key}"),
        )?;
    }
    for key in object.keys() {
        assert_ok(
            required.contains(&key.as_str()) || optional.contains(&key.as_str()),
            &format!("{label}: unexpected field {key}"),
        )?;
    }
    Ok(object)
}

fn map_value<'a>(object: &'a Map<String, Value>, key: &str, label: &str) -> Result<&'a Value> {
    object
        .get(key)
        .ok_or_else(|| format!("{label}: missing {key}"))
}

fn const_string(value: &Value, expected: &str, label: &str) -> Result<()> {
    assert_ok(value.as_str() == Some(expected), label)
}

fn const_number(value: &Value, expected: i64, label: &str) -> Result<()> {
    assert_ok(value.as_i64() == Some(expected), label)
}

fn b64_string(value: &Value, length: Option<usize>, label: &str) -> Result<Vec<u8>> {
    let encoded = value
        .as_str()
        .ok_or_else(|| format!("{label}: string required"))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| format!("{label}: {error}"))?;
    assert_ok(
        URL_SAFE_NO_PAD.encode(&decoded) == encoded,
        &format!("{label}: non-canonical base64url"),
    )?;
    if let Some(expected) = length {
        assert_ok(
            decoded.len() == expected,
            &format!("{label}: wrong byte length"),
        )?;
    }
    Ok(decoded)
}

fn valid_digest(value: &Value, label: &str) -> Result<()> {
    let bytes = b64_string(value, Some(32), label)?;
    assert_ok(bytes.len() == 32, label)
}

fn valid_cid(value: &Value, label: &str) -> Result<()> {
    let cid = value
        .as_str()
        .ok_or_else(|| format!("{label}: CID string required"))?;
    assert_ok(
        cid.len() == 59
            && cid.starts_with("bafkrei")
            && cid[7..]
                .bytes()
                .all(|byte| b"abcdefghijklmnopqrstuvwxyz234567".contains(&byte)),
        &format!("{label}: invalid CID"),
    )
}

fn valid_share_id(value: &Value, label: &str) -> Result<()> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{label}: string required"))?;
    assert_ok(
        !text.is_empty()
            && text.len() <= 128
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte)),
        &format!("{label}: invalid share ID"),
    )
}

fn valid_path(value: &Value, label: &str) -> Result<()> {
    let path = value
        .as_str()
        .ok_or_else(|| format!("{label}: path string required"))?;
    assert_ok(
        !path.is_empty()
            && path.len() <= 1024
            && !path.starts_with('/')
            && !path.contains("//")
            && !path.contains('\\')
            && !path.contains('?')
            && !path.contains('#')
            && !path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            && path.bytes().all(|byte| !(byte <= 0x1f || byte == 0x7f)),
        &format!("{label}: invalid path"),
    )
}

fn valid_origin(value: &Value, label: &str) -> Result<()> {
    let origin = value
        .as_str()
        .ok_or_else(|| format!("{label}: origin string required"))?;
    let rest = origin
        .strip_prefix("https://")
        .ok_or_else(|| format!("{label}: HTTPS origin required"))?;
    assert_ok(
        !rest.is_empty() && !rest.contains('/') && !rest.contains('*') && !rest.contains('?'),
        &format!("{label}: invalid origin"),
    )?;
    let host_port = rest.split_once(':');
    let host = host_port.map_or(rest, |(host, port)| {
        if port.is_empty()
            || port.starts_with('0')
            || !port.bytes().all(|byte| byte.is_ascii_digit())
        {
            ""
        } else {
            host
        }
    });
    assert_ok(
        !host.is_empty()
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            }),
        &format!("{label}: invalid origin host"),
    )
}

fn valid_time(value: &Value, label: &str) -> Result<i64> {
    let time = value
        .as_str()
        .ok_or_else(|| format!("{label}: time string required"))?;
    assert_ok(
        time.len() == 24
            && time.as_bytes()[4] == b'-'
            && time.as_bytes()[7] == b'-'
            && time.as_bytes()[10] == b'T'
            && time.as_bytes()[13] == b':'
            && time.as_bytes()[16] == b':'
            && time.as_bytes()[19] == b'.'
            && time.as_bytes()[23] == b'Z'
            && [0..4, 5..7, 8..10, 11..13, 14..16, 17..19, 20..23]
                .into_iter()
                .all(|range| time[range].bytes().all(|byte| byte.is_ascii_digit())),
        &format!("{label}: invalid RFC3339 millisecond time"),
    )?;
    let number = |range: std::ops::Range<usize>| -> Result<i64> {
        time[range]
            .parse::<i64>()
            .map_err(|error| format!("{label}: {error}"))
    };
    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    let hour = number(11..13)?;
    let minute = number(14..16)?;
    let second = number(17..19)?;
    let millis = number(20..23)?;
    assert_ok(
        (1..=12).contains(&month)
            && (1..=31).contains(&day)
            && hour < 24
            && minute < 60
            && second < 60
            && millis < 1000,
        &format!("{label}: invalid time component"),
    )?;
    // Howard Hinnant's proleptic Gregorian civil-date conversion, UTC only.
    let adjusted_year = year - i64::from(month <= 2);
    let era = (if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    }) / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146097 + day_of_era - 719468;
    Ok(days * 86_400 + hour * 3600 + minute * 60 + second)
}

fn valid_did(value: &Value, label: &str) -> Result<()> {
    let did = value
        .as_str()
        .ok_or_else(|| format!("{label}: DID string required"))?;
    let valid = if let Some(rest) = did.strip_prefix("did:web:") {
        !rest.is_empty()
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".:%_-".contains(&byte))
    } else if let Some(rest) = did.strip_prefix("did:pkh:") {
        !rest.is_empty()
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b":._-".contains(&byte))
    } else if let Some(rest) = did.strip_prefix("did:key:z") {
        !rest.is_empty() && rest.bytes().all(|byte| B58.contains(&byte))
    } else {
        false
    };
    assert_ok(valid, &format!("{label}: invalid DID"))
}

fn canonical_kid(did: &str) -> Result<String> {
    if did.starts_with("did:key:z") {
        did_key_bytes(did)?;
        Ok(format!("{}#{}", did, &did["did:key:".len()..]))
    } else if did.starts_with("did:web:") {
        Ok(format!("{did}#invitation-key-1"))
    } else {
        Err("cannot derive canonical kid".into())
    }
}

fn validate_source(source: &Value, expected_kind: &str) -> Result<()> {
    let source_object = if expected_kind == "sql" {
        exact_object(
            source,
            &[
                "kind",
                "space",
                "database",
                "path",
                "statement",
                "arguments",
                "argumentsDigest",
                "action",
            ],
            &[],
            "sourceSql",
        )?
    } else {
        exact_object(
            source,
            &["kind", "space", "path", "action"],
            &[],
            "sourceKv",
        )?
    };
    const_string(
        map_value(source_object, "kind", "source")?,
        expected_kind,
        "source kind",
    )?;
    valid_did(map_value(source_object, "space", "source")?, "source space")?;
    valid_path(map_value(source_object, "path", "source")?, "source path")?;
    let action = if expected_kind == "sql" {
        "tinycloud.sql/read"
    } else {
        "tinycloud.kv/get"
    };
    const_string(
        map_value(source_object, "action", "source")?,
        action,
        "source action",
    )?;
    if expected_kind == "sql" {
        let database = map_value(source_object, "database", "source")?
            .as_str()
            .ok_or("SQL database string")?;
        assert_ok(
            !database.is_empty()
                && database.len() <= 128
                && database
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
            "SQL database",
        )?;
        let statement = map_value(source_object, "statement", "source")?
            .as_str()
            .ok_or("SQL statement string")?;
        assert_ok(
            !statement.is_empty()
                && statement.len() <= 128
                && statement.bytes().enumerate().all(|(index, byte)| {
                    (index == 0 && byte.is_ascii_alphabetic())
                        || (index > 0 && (byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)))
                }),
            "SQL statement",
        )?;
        let arguments = map_object(source_object, "arguments")?;
        assert_ok(arguments.len() <= 32, "SQL argument count")?;
        for (name, value) in arguments {
            assert_ok(
                !name.is_empty()
                    && value
                        .as_i64()
                        .is_some_and(|number| number.unsigned_abs() <= 9_007_199_254_740_991),
                "SQL arguments must be safe integers",
            )?;
            assert_ok(
                jcs(value).is_ok(),
                "SQL argument must be canonical JSON integer",
            )?;
        }
        valid_digest(
            map_value(source_object, "argumentsDigest", "source")?,
            "argumentsDigest",
        )?;
        assert_ok(
            digest(jcs(&Value::Object(arguments.clone()))?.as_bytes())
                == map_text(source_object, "argumentsDigest")?,
            "SQL arguments digest",
        )?;
    }
    Ok(())
}

fn validate_proof(value: &Value, label: &str) -> Result<()> {
    let proof = exact_object(value, &["alg", "kid", "signature"], &[], label)?;
    const_string(map_value(proof, "alg", label)?, "EdDSA", "proof alg")?;
    let kid = map_value(proof, "kid", label)?
        .as_str()
        .ok_or("proof kid string")?;
    assert_ok(
        kid.len() >= 8
            && kid.len() <= 256
            && kid.matches('#').count() == 1
            && !kid.split('#').nth(1).unwrap_or("").is_empty()
            && !kid
                .split('#')
                .nth(1)
                .unwrap_or("")
                .contains(char::is_whitespace),
        "proof kid shape",
    )?;
    valid_did(
        &Value::String(kid.split('#').next().unwrap_or_default().into()),
        "proof kid DID",
    )?;
    b64_string(
        map_value(proof, "signature", label)?,
        Some(64),
        "proof signature",
    )?;
    Ok(())
}

fn valid_node_cid(value: &Value, label: &str) -> Result<()> {
    let text = value.as_str().ok_or(format!("{label}: CID string"))?;
    assert_ok(text.starts_with("bafkr4i") && text.len() == 59, label)
}

fn validate_exact_authority_material_message(message: &Value, _expected_kind: &str) -> Result<()> {
    let object = exact_object(
        message,
        &[
            "type",
            "version",
            "handle",
            "policyOwnerDid",
            "senderDid",
            "relationship",
            "mapping",
            "policyAuthorityBytes",
            "policyAuthorityCid",
            "policyEnforcementBytes",
            "policyEnforcementCid",
            "statusObservations",
            "enrollment",
            "attestation",
        ],
        &[],
        "exact authority material",
    )?;
    const_string(
        map_value(object, "type", "exact authority material")?,
        "TinyCloudShareAuthorityMaterial",
        "exact authority type",
    )?;
    const_number(
        map_value(object, "version", "exact authority material")?,
        1,
        "exact authority version",
    )?;
    let actual_handle = map_text(object, "handle")?;
    assert_ok(
        actual_handle == "amh_kv_001" || actual_handle == "amh_sql_001",
        "exact authority handle",
    )?;
    let owner = map_text(object, "policyOwnerDid")?;
    assert_ok(owner.starts_with("did:pkh:"), "policy owner DID")?;
    let sender = map_text(object, "senderDid")?;
    did_key_bytes(sender)?;
    assert_ok(owner != sender, "policy owner and sender must be distinct")?;
    let relationship = exact_object(
        map_value(object, "relationship", "exact authority material")?,
        &["policyOwnerDid", "senderDid", "authenticated"],
        &[],
        "authenticated relationship",
    )?;
    assert_ok(
        map_text(relationship, "policyOwnerDid")? == owner
            && map_text(relationship, "senderDid")? == sender
            && map_value(relationship, "authenticated", "relationship")? == &Value::Bool(true),
        "authenticated relationship mapping",
    )?;
    let mapping = exact_object(
        map_value(object, "mapping", "exact authority material")?,
        &[
            "sharePolicyCid",
            "shareDelegationCid",
            "policyAuthorityCid",
            "policyEnforcementCid",
        ],
        &[],
        "authority identifier mapping",
    )?;
    valid_cid(
        map_value(mapping, "sharePolicyCid", "mapping")?,
        "Share policy CID",
    )?;
    valid_cid(
        map_value(mapping, "shareDelegationCid", "mapping")?,
        "Share delegation CID",
    )?;
    valid_node_cid(
        map_value(mapping, "policyAuthorityCid", "mapping")?,
        "policy authority CID",
    )?;
    valid_node_cid(
        map_value(mapping, "policyEnforcementCid", "mapping")?,
        "policy enforcement CID",
    )?;
    for (bytes_key, cid_key, role) in [
        (
            "policyAuthorityBytes",
            "policyAuthorityCid",
            "policy-authority",
        ),
        (
            "policyEnforcementBytes",
            "policyEnforcementCid",
            "policy-enforcement",
        ),
    ] {
        let bytes = b64_string(
            map_value(object, bytes_key, "exact authority material")?,
            None,
            bytes_key,
        )?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| "parent JSON")?;
        assert_ok(
            jcs(&value)? == String::from_utf8(bytes).map_err(|_| "parent UTF-8")?,
            "parent canonical JCS",
        )?;
        let artifact = value.as_object().ok_or("parent object")?;
        assert_ok(
            artifact.get("schema").and_then(Value::as_str)
                == Some("xyz.tinycloud.policy/enforcement-delegation/v1")
                && artifact.get("role").and_then(Value::as_str) == Some(role),
            "exact Node role",
        )?;
        valid_node_cid(
            artifact
                .get("delegationCid")
                .ok_or("parent delegationCid")?,
            bytes_key,
        )?;
        assert_ok(
            artifact.get("delegationCid") == object.get(cid_key),
            "parent CID mapping",
        )?;
        let facts = artifact
            .get("facts")
            .and_then(Value::as_object)
            .ok_or("parent facts")?;
        assert_ok(!facts.is_empty(), "parent full facts")?;
        assert_ok(
            artifact
                .get("capabilities")
                .and_then(Value::as_array)
                .is_some_and(|items| !items.is_empty()),
            "parent capabilities",
        )?;
        assert_ok(
            artifact
                .get("signature")
                .and_then(Value::as_object)
                .is_some(),
            "parent signature",
        )?;
    }
    let statuses = map_value(object, "statusObservations", "exact authority material")?
        .as_array()
        .ok_or("status observations array")?;
    assert_ok(statuses.len() == 2, "one status observation per parent")?;
    for status in statuses {
        let row = status.as_object().ok_or("status observation object")?;
        for key in [
            "parentCid",
            "state",
            "sequence",
            "checkedAt",
            "freshUntil",
            "signerKid",
            "signature",
        ] {
            assert_ok(row.contains_key(key), "status observation field")?;
        }
        valid_node_cid(row.get("parentCid").unwrap(), "status parent CID")?;
        assert_ok(
            row.get("state").and_then(Value::as_str) == Some("active")
                && row.get("revokedAt") == Some(&Value::Null),
            "active irreversible status",
        )?;
        assert_ok(
            row.get("signature").and_then(Value::as_object).is_some(),
            "signed status observation",
        )?;
    }
    let enrollment = map_value(object, "enrollment", "exact authority material")?
        .as_object()
        .ok_or("enrollment object")?;
    assert_ok(
        enrollment
            .get("targetOrigin")
            .and_then(Value::as_str)
            .is_some()
            && enrollment
                .get("nodeAudience")
                .and_then(Value::as_str)
                .is_some()
            && enrollment.get("keyVersion").and_then(Value::as_i64) == Some(1)
            && enrollment.get("enabled") == Some(&Value::Bool(true)),
        "enrollment binding",
    )?;
    let attestation = map_value(object, "attestation", "exact authority material")?
        .as_object()
        .ok_or("attestation object")?;
    assert_ok(
        attestation.get("targetOrigin") == enrollment.get("targetOrigin")
            && attestation.get("nodeAudience") == enrollment.get("nodeAudience")
            && attestation.get("keyVersion") == enrollment.get("keyVersion")
            && attestation
                .get("signature")
                .and_then(Value::as_object)
                .is_some(),
        "runtime attestation binding",
    )?;
    Ok(())
}

fn validate_authority_material_message(message: &Value, expected_kind: &str) -> Result<()> {
    validate_exact_authority_material_message(message, expected_kind)
}
fn validate_message_schema(name: &str, message: &Value, expected_kind: &str) -> Result<()> {
    match name {
        "authorityMaterial" => validate_authority_material_message(message, expected_kind)?,
        "policy" => {
            let object = exact_object(
                message,
                &[
                    "type",
                    "version",
                    "recipientEmail",
                    "contentSource",
                    "contentSourceDigest",
                    "action",
                    "resource",
                    "expiresAt",
                    "issuerDid",
                ],
                &[],
                "policy",
            )?;
            const_string(
                map_value(object, "type", "policy")?,
                "TinyCloudSharePolicy",
                "policy type",
            )?;
            const_number(map_value(object, "version", "policy")?, 1, "policy version")?;
            assert_ok(
                strict_email(map_text(object, "recipientEmail")?),
                "policy email",
            )?;
            validate_source(map_value(object, "contentSource", "policy")?, expected_kind)?;
            valid_digest(
                map_value(object, "contentSourceDigest", "policy")?,
                "policy source digest",
            )?;
            assert_ok(
                digest(jcs(map_value(object, "contentSource", "policy")?)?.as_bytes())
                    == map_text(object, "contentSourceDigest")?,
                "policy source digest preimage",
            )?;
            const_string(
                map_value(object, "action", "policy")?,
                if expected_kind == "sql" {
                    "tinycloud.sql/read"
                } else {
                    "tinycloud.kv/get"
                },
                "policy action",
            )?;
            valid_path(map_value(object, "resource", "policy")?, "policy resource")?;
            valid_time(map_value(object, "expiresAt", "policy")?, "policy expiry")?;
            valid_did(map_value(object, "issuerDid", "policy")?, "policy issuer")?;
        }
        "envelope" => {
            let object = exact_object(
                message,
                &[
                    "version",
                    "shareId",
                    "delegation",
                    "authorizationTarget",
                    "target",
                    "display",
                    "expiry",
                ],
                &["content", "signature"],
                "envelope",
            )?;
            const_number(
                map_value(object, "version", "envelope")?,
                1,
                "envelope version",
            )?;
            valid_share_id(
                map_value(object, "shareId", "envelope")?,
                "envelope share ID",
            )?;
            let delegation = map_text(object, "delegation")?;
            assert_ok(
                !delegation.is_empty() && delegation.len() <= 65_536,
                "delegation",
            )?;
            let target = exact_object(
                map_value(object, "authorizationTarget", "envelope")?,
                &["kind", "policyCid", "policyBytes"],
                &[],
                "authorization target",
            )?;
            const_string(
                map_value(target, "kind", "authorization target")?,
                "policy",
                "authorization target kind",
            )?;
            valid_cid(
                map_value(target, "policyCid", "authorization target")?,
                "target policy CID",
            )?;
            let policy_bytes = b64_string(
                map_value(target, "policyBytes", "authorization target")?,
                None,
                "target policy bytes",
            )?;
            assert_ok(policy_bytes.len() <= 65_536, "policy byte limit")?;
            let envelope_target = exact_object(
                map_value(object, "target", "envelope")?,
                &["origin", "nodeAudience", "spaceId", "resource"],
                &[],
                "envelope target",
            )?;
            valid_origin(
                map_value(envelope_target, "origin", "envelope target")?,
                "envelope origin",
            )?;
            valid_did(
                map_value(envelope_target, "nodeAudience", "envelope target")?,
                "envelope audience",
            )?;
            let space_id = map_text(envelope_target, "spaceId")?;
            assert_ok(
                !space_id.is_empty() && space_id.len() <= 128 && !space_id.contains('/'),
                "envelope space ID",
            )?;
            let resource = exact_object(
                map_value(envelope_target, "resource", "envelope target")?,
                &["kind", "path"],
                &[],
                "envelope resource",
            )?;
            const_string(
                map_value(resource, "kind", "envelope resource")?,
                "exact",
                "envelope resource kind",
            )?;
            valid_path(
                map_value(resource, "path", "envelope resource")?,
                "envelope resource path",
            )?;
            let display = exact_object(
                map_value(object, "display", "envelope")?,
                &[],
                &["senderName", "filename", "recipientHint", "mode"],
                "display",
            )?;
            for key in ["senderName", "filename", "recipientHint"] {
                if let Some(value) = display.get(key) {
                    let text = value.as_str().ok_or("display text")?;
                    assert_ok(
                        text.len() <= 200 && !text.bytes().any(|byte| byte < 0x20 || byte == 0x7f),
                        "display byte boundary",
                    )?;
                }
            }
            if let Some(mode) = display.get("mode") {
                assert_ok(
                    matches!(
                        mode.as_str(),
                        Some("document") | Some("source") | Some("folder")
                    ),
                    "display mode",
                )?;
            }
            valid_time(map_value(object, "expiry", "envelope")?, "envelope expiry")?;
            if let Some(signature) = object.get("signature") {
                let signature = exact_object(
                    signature,
                    &["signerDid", "algorithm", "value"],
                    &[],
                    "envelope shipping signature",
                )?;
                let signer = map_value(signature, "signerDid", "shipping signature")?;
                did_key_bytes(signer.as_str().ok_or("shipping signer DID")?)?;
                const_string(
                    map_value(signature, "algorithm", "shipping signature")?,
                    "Ed25519",
                    "shipping algorithm",
                )?;
                b64_string(
                    map_value(signature, "value", "shipping signature")?,
                    Some(64),
                    "shipping signature value",
                )?;
            }
        }
        "inviteAuthorization" => validate_invite_authorization(message, expected_kind)?,
        "holderBinding" => validate_holder_binding(message, expected_kind)?,
        "policyChallenge" | "policyPresentation" | "policySession" | "readInvocation" => {
            validate_policy_artifact_message(name, message, expected_kind)?
        }
        _ => return Err(format!("unknown signed message schema {name}")),
    }
    Ok(())
}

fn validate_invite_authorization(message: &Value, expected_kind: &str) -> Result<()> {
    let object = exact_object(
        message,
        &[
            "type",
            "version",
            "jti",
            "senderDid",
            "shareCid",
            "shareId",
            "policyCid",
            "recipientEmail",
            "targetOrigin",
            "nodeAudience",
            "delegationCid",
            "authorityMaterialHandle",
            "authorityMaterialDigest",
            "returnOrigin",
            "documentName",
            "senderTrust",
            "contentSource",
            "contentSourceDigest",
            "shareExpiresAt",
            "issuedAt",
            "expiresAt",
            "reportAbuseToken",
        ],
        &[],
        "inviteAuthorization",
    )?;
    const_string(
        map_value(object, "type", "authorization")?,
        "TinyCloudShareInviteAuthorization",
        "authorization type",
    )?;
    const_number(
        map_value(object, "version", "authorization")?,
        1,
        "authorization version",
    )?;
    b64_string(
        map_value(object, "jti", "authorization")?,
        Some(16),
        "authorization JTI",
    )?;
    valid_did(
        map_value(object, "senderDid", "authorization")?,
        "sender DID",
    )?;
    valid_cid(
        map_value(object, "shareCid", "authorization")?,
        "authorization share CID",
    )?;
    valid_share_id(
        map_value(object, "shareId", "authorization")?,
        "authorization share ID",
    )?;
    valid_cid(
        map_value(object, "policyCid", "authorization")?,
        "authorization policy CID",
    )?;
    assert_ok(
        strict_email(map_text(object, "recipientEmail")?),
        "authorization email",
    )?;
    valid_origin(
        map_value(object, "targetOrigin", "authorization")?,
        "authorization origin",
    )?;
    valid_did(
        map_value(object, "nodeAudience", "authorization")?,
        "authorization audience",
    )?;
    const_string(
        map_value(object, "returnOrigin", "authorization")?,
        "https://share.tinycloud.xyz",
        "return origin",
    )?;
    let document_name = map_text(object, "documentName")?;
    assert_ok(
        !document_name.is_empty()
            && document_name.len() <= 200
            && !document_name
                .bytes()
                .any(|byte| byte <= 0x1f || byte == 0x7f),
        "document name byte boundary",
    )?;
    assert_ok(
        matches!(map_text(object, "senderTrust")?, "verified" | "unverified"),
        "sender trust",
    )?;
    validate_source(
        map_value(object, "contentSource", "authorization")?,
        expected_kind,
    )?;
    valid_digest(
        map_value(object, "contentSourceDigest", "authorization")?,
        "authorization source digest",
    )?;
    assert_ok(
        digest(jcs(map_value(object, "contentSource", "authorization")?)?.as_bytes())
            == map_text(object, "contentSourceDigest")?,
        "authorization source digest preimage",
    )?;
    valid_time(
        map_value(object, "shareExpiresAt", "authorization")?,
        "share expiry",
    )?;
    valid_time(
        map_value(object, "issuedAt", "authorization")?,
        "authorization issuedAt",
    )?;
    valid_time(
        map_value(object, "expiresAt", "authorization")?,
        "authorization expiresAt",
    )?;
    b64_string(
        map_value(object, "reportAbuseToken", "authorization")?,
        Some(16),
        "abuse token",
    )?;
    valid_cid(
        map_value(object, "delegationCid", "authorization")?,
        "authorization delegation CID",
    )?;
    assert_ok(
        map_text(object, "authorityMaterialHandle")?.starts_with("amh_"),
        "authorization authority handle",
    )?;
    valid_digest(
        map_value(object, "authorityMaterialDigest", "authorization")?,
        "authorization authority digest",
    )?;
    Ok(())
}

fn validate_holder_binding(message: &Value, expected_kind: &str) -> Result<()> {
    let object = exact_object(
        message,
        &[
            "type",
            "version",
            "redemptionId",
            "invitationId",
            "claimNonce",
            "shareCid",
            "shareId",
            "policyCid",
            "contentSource",
            "contentSourceDigest",
            "emailHash",
            "holderDid",
            "targetOrigin",
            "nodeAudience",
            "requestOrigin",
            "issuedAt",
            "expiresAt",
            "jti",
        ],
        &[
            "delegationCid",
            "authorityMaterialHandle",
            "authorityMaterialDigest",
        ],
        "holderBinding",
    )?;
    const_string(
        map_value(object, "type", "binding")?,
        "TinyCloudEmailClaimHolderBinding",
        "binding type",
    )?;
    const_number(
        map_value(object, "version", "binding")?,
        1,
        "binding version",
    )?;
    b64_string(
        map_value(object, "redemptionId", "binding")?,
        Some(16),
        "redemption ID",
    )?;
    b64_string(
        map_value(object, "invitationId", "binding")?,
        Some(16),
        "invitation ID",
    )?;
    b64_string(
        map_value(object, "claimNonce", "binding")?,
        Some(32),
        "claim nonce",
    )?;
    valid_cid(
        map_value(object, "shareCid", "binding")?,
        "binding share CID",
    )?;
    valid_share_id(map_value(object, "shareId", "binding")?, "binding share ID")?;
    valid_cid(
        map_value(object, "policyCid", "binding")?,
        "binding policy CID",
    )?;
    validate_source(
        map_value(object, "contentSource", "binding")?,
        expected_kind,
    )?;
    valid_digest(
        map_value(object, "contentSourceDigest", "binding")?,
        "binding source digest",
    )?;
    valid_digest(
        map_value(object, "emailHash", "binding")?,
        "binding email hash",
    )?;
    did_key_bytes(map_text(object, "holderDid")?)?;
    valid_origin(
        map_value(object, "targetOrigin", "binding")?,
        "binding origin",
    )?;
    valid_did(
        map_value(object, "nodeAudience", "binding")?,
        "binding audience",
    )?;
    const_string(
        map_value(object, "requestOrigin", "binding")?,
        "https://share.tinycloud.xyz",
        "binding request origin",
    )?;
    valid_time(
        map_value(object, "issuedAt", "binding")?,
        "binding issuedAt",
    )?;
    valid_time(
        map_value(object, "expiresAt", "binding")?,
        "binding expiresAt",
    )?;
    b64_string(
        map_value(object, "jti", "binding")?,
        Some(16),
        "binding JTI",
    )?;
    valid_cid(
        map_value(object, "delegationCid", "binding")?,
        "binding delegation CID",
    )?;
    assert_ok(
        map_text(object, "authorityMaterialHandle")?.starts_with("amh_"),
        "binding authority handle",
    )?;
    valid_digest(
        map_value(object, "authorityMaterialDigest", "binding")?,
        "binding authority digest",
    )?;
    Ok(())
}

fn validate_policy_artifact_message(
    name: &str,
    message: &Value,
    expected_kind: &str,
) -> Result<()> {
    let (required, label) = match name {
        "policyChallenge" => (
            &[
                "type",
                "version",
                "challengeId",
                "nonce",
                "shareCid",
                "shareId",
                "delegationCid",
                "policyCid",
                "contentSource",
                "contentSourceDigest",
                "holderDid",
                "targetOrigin",
                "nodeAudience",
                "action",
                "resource",
                "requestBodyDigest",
                "issuedAt",
                "expiresAt",
            ][..],
            "policyChallenge",
        ),
        "policyPresentation" => (
            &[
                "type",
                "version",
                "challengeId",
                "nonce",
                "shareCid",
                "shareId",
                "delegationCid",
                "policyCid",
                "contentSource",
                "contentSourceDigest",
                "holderDid",
                "targetOrigin",
                "nodeAudience",
                "credentialDigest",
                "action",
                "resource",
                "requestBodyDigest",
                "issuedAt",
                "expiresAt",
                "jti",
            ][..],
            "policyPresentation",
        ),
        "policySession" => (
            &[
                "type",
                "version",
                "sessionId",
                "shareCid",
                "shareId",
                "delegationCid",
                "policyCid",
                "contentSource",
                "contentSourceDigest",
                "holderDid",
                "targetOrigin",
                "nodeAudience",
                "action",
                "resource",
                "credentialDigest",
                "issuedAt",
                "expiresAt",
            ][..],
            "policySession",
        ),
        "readInvocation" => (
            &[
                "type",
                "version",
                "sessionId",
                "shareCid",
                "shareId",
                "policyCid",
                "delegationCid",
                "contentSource",
                "contentSourceDigest",
                "holderDid",
                "targetOrigin",
                "nodeAudience",
                "action",
                "resource",
                "requestBodyDigest",
                "issuedAt",
                "expiresAt",
                "jti",
            ][..],
            "readInvocation",
        ),
        _ => return Err("invalid policy artifact name".into()),
    };
    let object = exact_object(
        message,
        required,
        &["authorityMaterialHandle", "authorityMaterialDigest"],
        label,
    )?;
    assert_ok(
        object.contains_key("authorityMaterialHandle")
            && object.contains_key("authorityMaterialDigest"),
        "authority material propagation",
    )?;
    assert_ok(
        map_text(object, "authorityMaterialHandle")?.starts_with("amh_"),
        "authority material handle",
    )?;
    valid_digest(
        map_value(object, "authorityMaterialDigest", label)?,
        "authority material digest",
    )?;
    let expected_type = match name {
        "policyChallenge" => "TinyCloudSharePolicyChallenge",
        "policyPresentation" => "TinyCloudSharePolicyPresentation",
        "policySession" => "TinyCloudSharePolicySession",
        _ => "TinyCloudShareReadInvocation",
    };
    const_string(
        map_value(object, "type", label)?,
        expected_type,
        "artifact type",
    )?;
    const_number(map_value(object, "version", label)?, 1, "artifact version")?;
    let cid_fields = ["shareCid", "policyCid", "delegationCid"];
    for key in cid_fields.into_iter().filter(|key| !key.is_empty()) {
        valid_cid(map_value(object, key, label)?, key)?;
    }
    valid_share_id(map_value(object, "shareId", label)?, "artifact share ID")?;
    if let Some(value) = object.get("challengeId") {
        b64_string(value, Some(32), "challenge ID")?;
    }
    if let Some(value) = object.get("nonce") {
        b64_string(value, Some(32), "artifact nonce")?;
    }
    if let Some(value) = object.get("sessionId") {
        b64_string(value, Some(16), "session ID")?;
    }
    validate_source(map_value(object, "contentSource", label)?, expected_kind)?;
    valid_digest(
        map_value(object, "contentSourceDigest", label)?,
        "artifact source digest",
    )?;
    did_key_bytes(map_text(object, "holderDid")?)?;
    valid_origin(map_value(object, "targetOrigin", label)?, "artifact origin")?;
    valid_did(
        map_value(object, "nodeAudience", label)?,
        "artifact audience",
    )?;
    if let Some(value) = object.get("credentialDigest") {
        valid_digest(value, "credential digest")?;
    }
    const_string(
        map_value(object, "action", label)?,
        if expected_kind == "sql" {
            "tinycloud.sql/read"
        } else {
            "tinycloud.kv/get"
        },
        "artifact action",
    )?;
    valid_path(map_value(object, "resource", label)?, "artifact resource")?;
    if let Some(value) = object.get("requestBodyDigest") {
        valid_digest(value, "request body digest")?;
    }
    valid_time(map_value(object, "issuedAt", label)?, "artifact issuedAt")?;
    valid_time(map_value(object, "expiresAt", label)?, "artifact expiresAt")?;
    if let Some(value) = object.get("jti") {
        b64_string(value, Some(16), "artifact JTI")?;
    }
    Ok(())
}

fn jcs(value: &Value) -> Result<String> {
    match value {
        Value::Null => Ok("null".into()),
        Value::Bool(v) => Ok(if *v { "true" } else { "false" }.into()),
        Value::Number(v) => {
            if v.to_string() == "-0"
                || v.as_i64().is_none() && v.as_u64().is_none()
                || v.as_i64()
                    .is_some_and(|value| value.unsigned_abs() > 9_007_199_254_740_991)
                || v.as_u64()
                    .is_some_and(|value| value > 9_007_199_254_740_991)
            {
                return Err("fixture verifier only accepts safe integer JSON numbers".into());
            }
            Ok(v.to_string())
        }
        Value::String(v) => serde_json::to_string(v).map_err(|e| e.to_string()),
        Value::Array(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(jcs)
                .collect::<Result<Vec<_>>>()?
                .join(",")
        )),
        Value::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort_by_key(|key| key.encode_utf16().collect::<Vec<_>>());
            let mut members = Vec::with_capacity(keys.len());
            for key in keys {
                members.push(format!(
                    "{}:{}",
                    serde_json::to_string(key).map_err(|e| e.to_string())?,
                    jcs(object.get(key).ok_or("missing object member")?)?
                ));
            }
            Ok(format!("{{{}}}", members.join(",")))
        }
    }
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}
fn digest(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(sha256(bytes))
}
fn read_json(path: &Path) -> Result<Value> {
    serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {key}"))
}
fn object<'a>(value: &'a Value, key: &str) -> Result<&'a Map<String, Value>> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("missing object field {key}"))
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array field {key}"))
}
fn map_text<'a>(value: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {key}"))
}
fn map_object<'a>(value: &'a Map<String, Value>, key: &str) -> Result<&'a Map<String, Value>> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("missing object field {key}"))
}
fn map_array<'a>(value: &'a Map<String, Value>, key: &str) -> Result<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array field {key}"))
}
fn b64(value: &Value, key: &str) -> Result<Vec<u8>> {
    let encoded = text(value, key).map_err(|e| e.to_string())?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| format!("{key}: {e}"))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(format!("{key}: non-canonical base64url"));
    }
    Ok(decoded)
}
fn b64_map(value: &Map<String, Value>, key: &str) -> Result<Vec<u8>> {
    let encoded = map_text(value, key)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| format!("{key}: {e}"))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(format!("{key}: non-canonical base64url"));
    }
    Ok(decoded)
}
fn seed_verifying_key(domains: &Value, key: &str) -> Result<VerifyingKey> {
    let encoded = map_text(object(domains, "testKeys")?, key)?;
    assert_ok(
        encoded.len() == 64 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()),
        key,
    )?;
    let mut seed = [0u8; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
            .map_err(|e| e.to_string())?;
    }
    Ok(SigningKey::from_bytes(&seed).verifying_key())
}
fn assert_ok(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
fn base58_decode(input: &str) -> Result<Vec<u8>> {
    let mut big = vec![0u8];
    for byte in input.bytes() {
        let digit = B58
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or("bad base58")? as u32;
        let mut carry = digit;
        for value in big.iter_mut().rev() {
            let next = (*value as u32) * 58 + carry;
            *value = (next & 255) as u8;
            carry = next >> 8;
        }
        while carry != 0 {
            big.insert(0, (carry & 255) as u8);
            carry >>= 8;
        }
    }
    let zeros = input.bytes().take_while(|byte| *byte == b'1').count();
    let mut result = vec![0u8; zeros];
    result.extend(big.into_iter().skip_while(|byte| *byte == 0));
    Ok(result)
}
fn did_key_bytes(did: &str) -> Result<[u8; 32]> {
    let encoded = did.strip_prefix("did:key:z").ok_or("not did:key")?;
    let value = base58_decode(encoded)?;
    assert_ok(
        value.len() == 34 && value[0] == 0xed && value[1] == 1,
        "bad Ed25519 did:key multicodec",
    )?;
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&value[2..]);
    let key = VerifyingKey::from_bytes(&raw).map_err(|e| e.to_string())?;
    assert_ok(!key.is_weak(), "small-order Ed25519 key")?;
    Ok(raw)
}
fn cid(bytes: &[u8]) -> String {
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut input = vec![1, 0x55, 0x12, 0x20];
    input.extend(sha256(bytes));
    let mut buffer = 0u32;
    let mut bits = 0u8;
    let mut out = String::from("b");
    for byte in input {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(alphabet[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(alphabet[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}
fn verify_artifact(
    artifact: &Value,
    artifact_name: &str,
    domains: &Map<String, Value>,
    enrollment: &Value,
) -> Result<()> {
    verify_artifact_with_schema(artifact, artifact_name, domains, enrollment, true)
}

fn verify_artifact_with_schema(
    artifact: &Value,
    artifact_name: &str,
    domains: &Map<String, Value>,
    enrollment: &Value,
    validate_schema: bool,
) -> Result<()> {
    let artifact_object = exact_object(
        artifact,
        &[
            "name",
            "domain",
            "signerDid",
            "message",
            "jcs",
            "messageDigest",
            "signedBytesDigest",
            "signatureDigest",
            "signature",
        ],
        &[],
        artifact_name,
    )?;
    const_string(
        map_value(artifact_object, "name", artifact_name)?,
        artifact_name,
        "artifact name",
    )?;
    let domain = text(artifact, "domain")?;
    let registered_domain = domains
        .get(artifact_name)
        .and_then(Value::as_str)
        .ok_or("missing domain")?;
    assert_ok(
        domain == registered_domain && domain.ends_with('\0'),
        "registry domain mismatch",
    )?;
    let message = artifact.get("message").ok_or("missing artifact message")?;
    let expected_kind = message
        .get("contentSource")
        .and_then(|source| source.get("kind"))
        .or_else(|| {
            message
                .get("policyAuthority")
                .and_then(|authority| authority.get("contentSource"))
                .and_then(|source| source.get("kind"))
        })
        .and_then(Value::as_str)
        .unwrap_or("kv");
    if validate_schema {
        validate_message_schema(artifact_name, message, expected_kind)?;
    }
    let canonical = jcs(message)?;
    assert_ok(canonical == text(artifact, "jcs")?, "JCS mismatch")?;
    let signed = [domain.as_bytes(), canonical.as_bytes()].concat();
    assert_ok(
        digest(canonical.as_bytes()) == text(artifact, "messageDigest")?,
        "message digest mismatch",
    )?;
    assert_ok(
        digest(&signed) == text(artifact, "signedBytesDigest")?,
        "signed bytes digest mismatch",
    )?;
    let signature_object = exact_object(
        map_value(artifact_object, "signature", artifact_name)?,
        &["alg", "kid", "value"],
        &[],
        "artifact signature",
    )?;
    const_string(
        map_value(signature_object, "alg", "artifact signature")?,
        "EdDSA",
        "artifact signature algorithm",
    )?;
    let signature = b64_string(
        map_value(signature_object, "value", "artifact signature")?,
        Some(64),
        "artifact signature",
    )?;
    assert_canonical_ed25519_s(&signature)?;
    assert_ok(
        digest(&signature) == text(artifact, "signatureDigest")?,
        "signature digest mismatch",
    )?;
    let signer = text(artifact, "signerDid")?;
    valid_did(&Value::String(signer.into()), "artifact signer DID")?;
    let node_signed = matches!(
        artifact_name,
        "inviteAuthorization" | "policyChallenge" | "policySession"
    );
    let expected_kid = if node_signed {
        assert_ok(
            signer == text(enrollment, "nodeAudience")?,
            "node signer DID mismatch",
        )?;
        text(enrollment, "invitationKid")?.to_string()
    } else {
        assert_ok(
            signer.starts_with("did:key:z"),
            "holder/sender signer must be did:key",
        )?;
        canonical_kid(signer)?
    };
    assert_ok(
        map_text(signature_object, "kid")? == expected_kid,
        "non-canonical artifact kid",
    )?;
    let public = if node_signed {
        let raw = b64(enrollment, "invitationPublicKey")?;
        assert_ok(raw.len() == 32, "node public key length")?;
        let expected = raw.clone();
        assert_ok(
            signer == text(enrollment, "nodeAudience")?
                && expected_kid == text(enrollment, "invitationKid")?,
            "node enrollment authority mismatch",
        )?;
        expected
            .try_into()
            .map_err(|_| "node public key length".to_string())?
    } else {
        did_key_bytes(signer)?
    };
    let key = VerifyingKey::from_bytes(&public).map_err(|e| e.to_string())?;
    let sig = Signature::from_slice(&signature).map_err(|e| e.to_string())?;
    key.verify_strict(&signed, &sig)
        .map_err(|e| format!("{artifact_name}: {e}"))?;
    // The artifact's signer key and kid are independently bound above. Keep this
    // explicit check so a valid signature cannot be moved between artifact roles.
    if artifact_name == "policy" || artifact_name == "envelope" {
        assert_ok(
            signer != text(enrollment, "nodeAudience")?,
            "sender/node key confusion",
        )?;
    }
    Ok(())
}

fn assert_canonical_ed25519_s(signature: &[u8]) -> Result<()> {
    assert_ok(signature.len() == 64, "Ed25519 signature length")?;
    // Ed25519 signatures encode S as a little-endian scalar. Strict verification
    // rejects S >= L; checking the encoding explicitly keeps that rejection
    // independent of the crypto crate's parser behavior.
    const GROUP_ORDER: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let s = &signature[32..];
    let canonical = s.iter().rev().cmp(GROUP_ORDER.iter().rev()).is_lt();
    assert_ok(canonical, "non-canonical Ed25519 S")
}
fn verify_signature_core(artifact: &Value, artifact_name: &str, enrollment: &Value) -> Result<()> {
    let domain = text(artifact, "domain")?;
    let canonical = jcs(artifact.get("message").ok_or("missing artifact message")?)?;
    let signed = [domain.as_bytes(), canonical.as_bytes()].concat();
    let signature_object = object(artifact, "signature")?;
    let encoded = map_text(signature_object, "value")?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|e| e.to_string())?;
    assert_ok(
        URL_SAFE_NO_PAD.encode(&signature_bytes) == encoded && signature_bytes.len() == 64,
        "invalid signature representation",
    )?;
    let signer = text(artifact, "signerDid")?;
    let public = if artifact_name == "inviteAuthorization"
        || artifact_name == "policyChallenge"
        || artifact_name == "policySession"
    {
        let raw = b64(enrollment, "invitationPublicKey")?;
        raw.try_into()
            .map_err(|_| "node public key length".to_string())?
    } else {
        did_key_bytes(signer)?
    };
    let key = VerifyingKey::from_bytes(&public).map_err(|e| e.to_string())?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|e| e.to_string())?;
    key.verify_strict(&signed, &signature)
        .map_err(|e| format!("{artifact_name}: {e}"))
}
fn proof_matches(
    response: &Value,
    artifact: &Value,
    enrollment: &Value,
    label: &str,
) -> Result<()> {
    let proof = exact_object(
        response.get("proof").ok_or("proof")?,
        &["alg", "kid", "signature"],
        &[],
        "wrapper proof",
    )?;
    let signature = exact_object(
        artifact.get("signature").ok_or("artifact signature")?,
        &["alg", "kid", "value"],
        &[],
        "artifact signature",
    )?;
    let kid = text(enrollment, "invitationKid")?;
    assert_ok(
        map_text(signature, "alg")? == "EdDSA"
            && map_text(proof, "alg")? == "EdDSA"
            && map_text(signature, "kid")? == kid
            && map_text(proof, "kid")? == kid
            && text(artifact, "signerDid")? == text(enrollment, "nodeAudience")?
            && map_text(proof, "signature")? == map_text(signature, "value")?,
        label,
    )?;
    b64_string(
        map_value(proof, "signature", "proof")?,
        Some(64),
        "proof signature",
    )?;
    Ok(())
}

fn validate_node_enrollment(enrollment: &Value, domains: &Value) -> Result<()> {
    let authority = exact_object(
        domains
            .get("nodeAuthority")
            .ok_or("node authority registry")?,
        &[
            "origin",
            "nodeAudience",
            "activeKeyVersion",
            "keyVersions",
            "rules",
        ],
        &[],
        "node authority registry",
    )?;
    const_string(
        map_value(authority, "origin", "node authority")?,
        "https://node.example",
        "authority origin",
    )?;
    const_string(
        map_value(authority, "nodeAudience", "node authority")?,
        "did:web:node.example",
        "authority audience",
    )?;
    const_number(
        map_value(authority, "activeKeyVersion", "node authority")?,
        1,
        "active node key version",
    )?;
    let rules = exact_object(
        map_value(authority, "rules", "node authority")?,
        &[
            "originAudienceImmutable",
            "enabledRequired",
            "rotationRequiresHigherVersion",
            "retiredVersionsReject",
        ],
        &[],
        "node authority rules",
    )?;
    for key in [
        "originAudienceImmutable",
        "enabledRequired",
        "rotationRequiresHigherVersion",
        "retiredVersionsReject",
    ] {
        assert_ok(
            rules.get(key) == Some(&Value::Bool(true)),
            "node authority rule",
        )?;
    }
    let object = exact_object(
        enrollment,
        &[
            "targetOrigin",
            "nodeAudience",
            "invitationKid",
            "invitationPublicKey",
            "keyVersion",
            "enabled",
        ],
        &[],
        "trusted node enrollment",
    )?;
    valid_origin(
        map_value(object, "targetOrigin", "enrollment")?,
        "enrollment origin",
    )?;
    valid_did(
        map_value(object, "nodeAudience", "enrollment")?,
        "enrollment audience",
    )?;
    let audience = map_text(object, "nodeAudience")?;
    assert_ok(
        audience == "did:web:node.example",
        "untrusted node audience",
    )?;
    let kid = map_text(object, "invitationKid")?;
    assert_ok(
        kid == "did:web:node.example#invitation-key-1",
        "node authority kid",
    )?;
    assert_ok(!kid.contains(char::is_whitespace), "node kid whitespace")?;
    b64_string(
        map_value(object, "invitationPublicKey", "enrollment")?,
        Some(32),
        "enrollment public key",
    )?;
    const_number(
        map_value(object, "keyVersion", "enrollment")?,
        1,
        "enrollment key version",
    )?;
    assert_ok(
        object.get("enabled") == Some(&Value::Bool(true)),
        "node enrollment disabled",
    )?;
    let key_versions = map_array(authority, "keyVersions")?;
    assert_ok(key_versions.len() == 2, "node key rotation registry")?;
    let active = exact_object(
        &key_versions[0],
        &["keyVersion", "invitationKid", "publicKey", "state"],
        &[],
        "active node key",
    )?;
    const_number(
        map_value(active, "keyVersion", "active node key")?,
        1,
        "active key version",
    )?;
    const_string(
        map_value(active, "invitationKid", "active node key")?,
        kid,
        "active key ID",
    )?;
    const_string(
        map_value(active, "state", "active node key")?,
        "active",
        "active key state",
    )?;
    assert_ok(
        b64_string(
            map_value(active, "publicKey", "active node key")?,
            Some(32),
            "active node public key",
        )? == b64_string(
            map_value(object, "invitationPublicKey", "enrollment")?,
            Some(32),
            "enrollment public key",
        )?,
        "active enrollment key binding",
    )?;
    let retired = exact_object(
        &key_versions[1],
        &["keyVersion", "invitationKid", "publicKey", "state"],
        &[],
        "retired node key",
    )?;
    const_number(
        map_value(retired, "keyVersion", "retired node key")?,
        2,
        "retired key version",
    )?;
    const_string(
        map_value(retired, "state", "retired node key")?,
        "retired",
        "retired key state",
    )?;
    let node_key = seed_verifying_key(domains, "nodeSeedHex")?;
    assert_ok(
        b64_string(
            map_value(object, "invitationPublicKey", "enrollment")?,
            Some(32),
            "enrollment public key",
        )? == node_key.to_bytes(),
        "enrollment public key does not match authority",
    )?;
    Ok(())
}

fn validate_capability_registry(domains: &Value) -> Result<()> {
    let capabilities = object(domains, "capabilities")?;
    let witness = exact_object(
        capabilities.get("witness").ok_or("witness capability")?,
        &[
            "id",
            "version",
            "origin",
            "returnOrigin",
            "routes",
            "mailProvider",
            "status",
        ],
        &[],
        "witness capability",
    )?;
    const_string(
        map_value(witness, "id", "witness")?,
        "tinycloud.share-email-claim",
        "witness ID",
    )?;
    const_number(
        map_value(witness, "version", "witness")?,
        1,
        "witness version",
    )?;
    valid_origin(map_value(witness, "origin", "witness")?, "witness origin")?;
    const_string(
        map_value(witness, "returnOrigin", "witness")?,
        "https://share.tinycloud.xyz",
        "witness return origin",
    )?;
    const_string(
        map_value(witness, "mailProvider", "witness")?,
        "resend",
        "mail provider",
    )?;
    const_string(
        map_value(witness, "status", "witness")?,
        "disabled-until-real-provider",
        "witness status",
    )?;
    let witness_routes = map_array(witness, "routes")?;
    assert_ok(
        witness_routes.len() == 5
            && witness_routes
                .iter()
                .map(Value::as_str)
                .collect::<HashSet<_>>()
                == [
                    Some("/v1/share-email/invitations"),
                    Some("/v1/share-email/invitations/resend"),
                    Some("/v1/share-email/claims/activate"),
                    Some("/v1/share-email/claims/challenge"),
                    Some("/v1/share-email/claims/redeem"),
                ]
                .into_iter()
                .collect(),
        "witness capability routes",
    )?;
    let node = exact_object(
        capabilities.get("node").ok_or("node capability")?,
        &[
            "id",
            "version",
            "origin",
            "routes",
            "contentKinds",
            "status",
        ],
        &[],
        "node capability",
    )?;
    const_string(
        map_value(node, "id", "node")?,
        "tinycloud.node-policy-email-v1",
        "node ID",
    )?;
    const_number(map_value(node, "version", "node")?, 1, "node version")?;
    const_string(
        map_value(node, "origin", "node")?,
        "https://node.example",
        "node origin",
    )?;
    const_string(
        map_value(node, "status", "node")?,
        "disabled-until-authority-ready",
        "node status",
    )?;
    let routes = map_array(node, "routes")?;
    assert_ok(
        routes.len() == 4
            && routes.iter().all(|route| {
                matches!(
                    route.as_str(),
                    Some("/share/v1/invitations/authorize")
                        | Some("/share/v1/policy/challenges")
                        | Some("/share/v1/policy/session")
                        | Some("/share/v1/read")
                )
            }),
        "node capability routes",
    )?;
    let content_kinds = map_array(node, "contentKinds")?;
    assert_ok(
        content_kinds.len() == 2
            && content_kinds
                .iter()
                .any(|value| value.as_str() == Some("kv"))
            && content_kinds
                .iter()
                .any(|value| value.as_str() == Some("sql")),
        "node capability content kinds",
    )?;
    Ok(())
}

fn validate_issuer_trust(domains: &Value, issuer_key: &VerifyingKey) -> Result<()> {
    let trust = exact_object(
        domains.get("issuerTrust").ok_or("issuer trust registry")?,
        &[
            "issuerDid",
            "vct",
            "keyVersion",
            "kid",
            "publicKey",
            "enabled",
        ],
        &[],
        "issuer trust registry",
    )?;
    const_string(
        map_value(trust, "issuerDid", "issuer trust")?,
        "did:web:issuer.credentials.org",
        "issuer trust DID",
    )?;
    const_string(
        map_value(trust, "vct", "issuer trust")?,
        "opencredentials.email/v1",
        "issuer trust VCT",
    )?;
    const_number(
        map_value(trust, "keyVersion", "issuer trust")?,
        1,
        "issuer trust key version",
    )?;
    const_string(
        map_value(trust, "kid", "issuer trust")?,
        "did:web:issuer.credentials.org#email-signing-key-1",
        "issuer trust kid",
    )?;
    assert_ok(
        trust.get("enabled") == Some(&Value::Bool(true)),
        "issuer key disabled",
    )?;
    assert_ok(
        b64_string(
            map_value(trust, "publicKey", "issuer trust")?,
            Some(32),
            "issuer trust public key",
        )? == issuer_key.to_bytes(),
        "issuer trust public key",
    )?;
    Ok(())
}
fn verify_sd_jwt_signature_prerequisites(
    credential: &Map<String, Value>,
    claims: &Map<String, Value>,
    issuer_key: &VerifyingKey,
) -> Result<()> {
    let credential_text = map_text(credential, "credential")?;
    let parts: Vec<&str> = credential_text.split('~').collect();
    assert_ok(
        parts.len() == 3 && parts[2].is_empty(),
        "SD-JWT compact form",
    )?;
    let jwt_parts: Vec<&str> = parts[0].split('.').collect();
    assert_ok(jwt_parts.len() == 3, "SD-JWT JWT segments")?;
    let header_bytes = URL_SAFE_NO_PAD
        .decode(jwt_parts[0])
        .map_err(|e| e.to_string())?;
    assert_ok(
        URL_SAFE_NO_PAD.encode(&header_bytes) == jwt_parts[0],
        "SD-JWT header encoding",
    )?;
    let header: Value = serde_json::from_slice(&header_bytes).map_err(|e| e.to_string())?;
    let header_object = header.as_object().ok_or("SD-JWT header object")?;
    assert_ok(
        header_object.len() == 1
            && header_object.get("alg").and_then(Value::as_str) == Some("EdDSA"),
        "SD-JWT issuer header",
    )?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(jwt_parts[1])
        .map_err(|e| e.to_string())?;
    assert_ok(
        URL_SAFE_NO_PAD.encode(&payload_bytes) == jwt_parts[1],
        "SD-JWT payload encoding",
    )?;
    let payload: Value = serde_json::from_slice(&payload_bytes).map_err(|e| e.to_string())?;
    assert_ok(
        payload.as_object() == Some(claims),
        "SD-JWT signed payload differs from detached claims",
    )?;
    let issuer_jws = exact_object(
        map_value(credential, "issuerJws", "credential")?,
        &["signingInput", "signingInputDigest", "signature"],
        &[],
        "issuer JWS",
    )?;
    let signing_input = format!("{}.{}", jwt_parts[0], jwt_parts[1]);
    assert_ok(
        signing_input == map_text(issuer_jws, "signingInput")?
            && digest(signing_input.as_bytes()) == map_text(issuer_jws, "signingInputDigest")?,
        "SD-JWT issuer preimages",
    )?;
    let issuer_signature = b64_string(
        map_value(issuer_jws, "signature", "issuer JWS")?,
        Some(64),
        "issuer signature",
    )?;
    let jwt_signature = URL_SAFE_NO_PAD
        .decode(jwt_parts[2])
        .map_err(|e| e.to_string())?;
    assert_ok(
        URL_SAFE_NO_PAD.encode(&jwt_signature) == jwt_parts[2] && jwt_signature.len() == 64,
        "SD-JWT issuer signature encoding",
    )?;
    assert_ok(
        map_text(issuer_jws, "signature")? == jwt_parts[2],
        "SD-JWT issuer signature binding",
    )?;
    assert_canonical_ed25519_s(&jwt_signature)?;
    assert_ok(
        issuer_signature == jwt_signature,
        "SD-JWT issuer signature copy",
    )?;
    let signature = Signature::from_slice(&jwt_signature).map_err(|e| e.to_string())?;
    issuer_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|e| format!("SD-JWT issuer signature: {e}"))
}

fn validate_sd_jwt(scenario: &Value, issuer_key: &VerifyingKey) -> Result<()> {
    let credential = exact_object(
        scenario.get("credential").ok_or("credential")?,
        &[
            "format",
            "credential",
            "holderDid",
            "expiresAt",
            "issuerDid",
            "vct",
            "claims",
            "disclosures",
            "credentialDigest",
            "issuerJws",
        ],
        &[],
        "credential",
    )?;
    const_string(
        map_value(credential, "format", "credential")?,
        "vc+sd-jwt",
        "credential format",
    )?;
    const_string(
        map_value(credential, "vct", "credential")?,
        "opencredentials.email/v1",
        "credential vct",
    )?;
    let credential_text = map_text(credential, "credential")?;
    assert_ok(
        !credential_text.is_empty() && credential_text.len() <= 65_536,
        "credential byte limit",
    )?;
    valid_digest(
        map_value(credential, "credentialDigest", "credential")?,
        "credential digest",
    )?;
    assert_ok(
        digest(credential_text.as_bytes()) == map_text(credential, "credentialDigest")?,
        "credential digest preimage",
    )?;
    let credential_holder = map_text(credential, "holderDid")?;
    did_key_bytes(credential_holder)?;
    let issuer_did = map_text(credential, "issuerDid")?;
    assert_ok(
        issuer_did == "did:web:issuer.credentials.org",
        "untrusted credential issuer",
    )?;
    valid_did(&Value::String(issuer_did.into()), "credential issuer DID")?;
    let share_expiry = valid_time(
        &Value::String(map_text(object(scenario, "authorization")?, "shareExpiresAt")?.into()),
        "share expiry",
    )?;
    assert_ok(
        map_text(credential, "expiresAt")?
            == map_text(object(scenario, "authorization")?, "shareExpiresAt")?,
        "credential/share expiry mismatch",
    )?;
    assert_ok(
        valid_time(
            map_value(credential, "expiresAt", "credential")?,
            "credential expiry",
        )? == share_expiry,
        "credential expiry value",
    )?;
    let claims = exact_object(
        map_value(credential, "claims", "credential")?,
        &[
            "iss",
            "sub",
            "iat",
            "nbf",
            "exp",
            "jti",
            "vct",
            "tinycloud_share",
            "_sd_alg",
            "_sd",
        ],
        &[],
        "SD-JWT claims",
    )?;
    // Authenticate the complete signed payload before evaluating any holder,
    // time, issuer, or scope semantics.  A re-signed candidate therefore
    // cannot use a semantic failure to mask an invalid signature.
    verify_sd_jwt_signature_prerequisites(credential, claims, issuer_key)?;
    const_string(
        map_value(claims, "vct", "SD-JWT claims")?,
        "opencredentials.email/v1",
        "SD-JWT claims vct",
    )?;
    let claim_jti = map_text(claims, "jti")?;
    assert_ok(
        !claim_jti.is_empty() && claim_jti.len() <= 256,
        "SD-JWT JTI",
    )?;
    assert_ok(map_text(claims, "_sd_alg")? == "sha-256", "SD-JWT _sd_alg")?;
    let sd = map_array(claims, "_sd")?;
    assert_ok(sd.len() == 1, "SD-JWT _sd cardinality")?;
    let disclosure = map_array(credential, "disclosures")?;
    assert_ok(disclosure.len() == 1, "SD-JWT disclosure cardinality")?;
    let disclosure = &disclosure[0];
    let disclosure_object = exact_object(
        disclosure,
        &["path", "salt", "encoded", "digest", "value"],
        &[],
        "SD-JWT disclosure",
    )?;
    const_string(
        map_value(disclosure_object, "path", "disclosure")?,
        "/email",
        "SD-JWT disclosure path",
    )?;
    let salt = text(disclosure, "salt")?;
    let encoded = text(disclosure, "encoded")?;
    let encoded_bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|e| e.to_string())?;
    assert_ok(
        URL_SAFE_NO_PAD.encode(&encoded_bytes) == encoded,
        "SD-JWT disclosure encoding",
    )?;
    let decoded: Value = serde_json::from_slice(&encoded_bytes).map_err(|e| e.to_string())?;
    let values = decoded.as_array().ok_or("SD-JWT disclosure array")?;
    assert_ok(values.len() == 3, "SD-JWT disclosure shape")?;
    assert_ok(
        values[0].as_str() == Some(salt)
            && values[1].as_str() == Some("email")
            && values[2].as_str() == Some(text(scenario, "canonicalEmail")?),
        "SD-JWT email disclosure",
    )?;
    assert_ok(
        digest(encoded.as_bytes()) == text(disclosure, "digest")?
            && sd[0].as_str() == Some(text(disclosure, "digest")?),
        "SD-JWT disclosure digest",
    )?;
    assert_ok(
        salt == text(scenario, "sdJwtSalt")?,
        "SD-JWT deterministic salt",
    )?;
    b64_string(
        map_value(disclosure_object, "salt", "disclosure")?,
        Some(16),
        "SD-JWT salt",
    )?;
    assert_ok(
        strict_email(text(disclosure, "value")?),
        "SD-JWT disclosed email",
    )?;
    let parts: Vec<&str> = credential_text.split('~').collect();
    assert_ok(
        parts.len() == 3 && parts[1] == encoded && parts[2].is_empty(),
        "SD-JWT compact form",
    )?;
    let jwt_parts: Vec<&str> = parts[0].split('.').collect();
    assert_ok(jwt_parts.len() == 3, "SD-JWT JWT segments")?;
    let header_bytes = URL_SAFE_NO_PAD
        .decode(jwt_parts[0])
        .map_err(|e| e.to_string())?;
    assert_ok(
        URL_SAFE_NO_PAD.encode(&header_bytes) == jwt_parts[0],
        "SD-JWT header encoding",
    )?;
    let header: Value = serde_json::from_slice(&header_bytes).map_err(|e| e.to_string())?;
    let header_object = header.as_object().ok_or("SD-JWT header object")?;
    assert_ok(
        header_object.len() == 1
            && header_object.get("alg").and_then(Value::as_str) == Some("EdDSA"),
        "SD-JWT issuer header",
    )?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(jwt_parts[1])
        .map_err(|e| e.to_string())?;
    assert_ok(
        URL_SAFE_NO_PAD.encode(&payload_bytes) == jwt_parts[1],
        "SD-JWT payload encoding",
    )?;
    let payload: Value = serde_json::from_slice(&payload_bytes).map_err(|e| e.to_string())?;
    assert_ok(
        payload.as_object() == Some(claims),
        "SD-JWT signed payload differs from detached claims",
    )?;
    let scope = map_object(claims, "tinycloud_share")?;
    assert_ok(scope.len() == 4, "SD-JWT scope shape")?;
    assert_ok(
        map_text(scope, "share_cid")? == text(scenario, "shareCid")?
            && map_text(scope, "share_id")? == text(scenario, "shareId")?
            && map_text(scope, "policy_cid")? == text(scenario, "policyCid")?
            && map_text(scope, "node_audience")?
                == map_text(object(scenario, "authorization")?, "nodeAudience")?,
        "SD-JWT signed scope",
    )?;
    let issuer_jws = exact_object(
        map_value(credential, "issuerJws", "credential")?,
        &["signingInput", "signingInputDigest", "signature"],
        &[],
        "issuer JWS",
    )?;
    let signing_input = format!("{}.{}", jwt_parts[0], jwt_parts[1]);
    assert_ok(
        signing_input == map_text(issuer_jws, "signingInput")?
            && digest(signing_input.as_bytes()) == map_text(issuer_jws, "signingInputDigest")?
            && digest(credential_text.as_bytes()) == map_text(credential, "credentialDigest")?,
        "SD-JWT issuer preimages",
    )?;
    b64_string(
        map_value(issuer_jws, "signature", "issuer JWS")?,
        Some(64),
        "issuer signature",
    )?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(jwt_parts[2])
        .map_err(|e| e.to_string())?;
    assert_ok(
        URL_SAFE_NO_PAD.encode(&signature_bytes) == jwt_parts[2] && signature_bytes.len() == 64,
        "SD-JWT issuer signature encoding",
    )?;
    let issuer_did = map_text(claims, "iss")?;
    assert_ok(
        map_text(credential, "issuerDid")? == issuer_did,
        "SD-JWT issuer DID binding",
    )?;
    assert_ok(
        map_text(claims, "iss")? == issuer_did,
        "SD-JWT issuer trust binding",
    )?;
    let binding_holder = text(artifact_message(scenario, "holderBinding")?, "holderDid")?;
    assert_ok(
        credential_holder == map_text(claims, "sub")? && credential_holder == binding_holder,
        "SD-JWT holder equality",
    )?;
    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or("SD-JWT iat")?;
    let nbf = claims
        .get("nbf")
        .and_then(Value::as_i64)
        .ok_or("SD-JWT nbf")?;
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or("SD-JWT exp")?;
    assert_ok(
        iat >= 0 && nbf >= 0 && exp >= 0 && iat <= nbf && nbf < exp,
        "SD-JWT date ordering",
    )?;
    assert_ok(exp == share_expiry, "SD-JWT share expiry")?;
    let evaluation_time = valid_time(
        scenario.get("evaluationTime").ok_or("evaluation time")?,
        "evaluation time",
    )?;
    let clock_skew = scenario
        .get("clockSkewSeconds")
        .and_then(Value::as_i64)
        .ok_or("clock skew")?;
    assert_ok((0..=300).contains(&clock_skew), "clock skew bounds")?;
    let issued_at = valid_time(
        &Value::String(map_text(object(scenario, "authorization")?, "issuedAt")?.into()),
        "authorization issuedAt",
    )?;
    assert_ok(
        iat == issued_at && nbf == issued_at,
        "SD-JWT issued-at binding",
    )?;
    assert_ok(
        iat <= evaluation_time + clock_skew,
        "SD-JWT iat is from the future",
    )?;
    assert_ok(
        nbf <= evaluation_time + clock_skew,
        "SD-JWT nbf is not active",
    )?;
    assert_ok(exp > evaluation_time - clock_skew, "SD-JWT expired")?;
    Ok(())
}

fn validate_credential_semantic_boundaries(
    scenario: &Value,
) -> std::result::Result<(), NegativeRejection> {
    let credential = object(scenario, "credential")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    let claims = map_object(credential, "claims")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;

    if map_text(credential, "vct")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
        != "opencredentials.email/v1"
        || map_text(claims, "vct")
            .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
            != "opencredentials.email/v1"
    {
        return Err(rejection(
            RejectionStage::CredentialVct,
            "credential VCT is not the trusted email profile",
        ));
    }

    let trusted_issuer = "did:web:issuer.credentials.org";
    if map_text(credential, "issuerDid")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
        != trusted_issuer
        || map_text(claims, "iss")
            .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
            != trusted_issuer
    {
        return Err(rejection(
            RejectionStage::IssuerTrust,
            "credential issuer is not trusted",
        ));
    }

    let credential_holder = map_text(credential, "holderDid")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    did_key_bytes(credential_holder)
        .map_err(|detail| rejection(RejectionStage::CredentialHolder, detail))?;
    let claim_holder = map_text(claims, "sub")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    let binding_holder = text(
        artifact_message(scenario, "holderBinding")
            .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?,
        "holderDid",
    )
    .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    if credential_holder != claim_holder || credential_holder != binding_holder {
        return Err(rejection(
            RejectionStage::CredentialHolder,
            "credential holder does not match its subject and binding",
        ));
    }

    let scope = map_object(claims, "tinycloud_share")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    let scope_matches = map_text(scope, "share_cid")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
        == text(scenario, "shareCid")
            .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
        && map_text(scope, "share_id")
            .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
            == text(scenario, "shareId")
                .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
        && map_text(scope, "policy_cid")
            .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
            == text(scenario, "policyCid")
                .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    if !scope_matches {
        return Err(rejection(
            RejectionStage::CredentialScope,
            "credential scope does not match the share",
        ));
    }

    let authorization = object(scenario, "authorization")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    let share_expiry = valid_time(
        &Value::String(
            map_text(authorization, "shareExpiresAt")
                .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
                .into(),
        ),
        "share expiry",
    )
    .map_err(|detail| rejection(RejectionStage::CredentialTime, detail))?;
    let credential_expiry = valid_time(
        &Value::String(
            map_text(credential, "expiresAt")
                .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
                .into(),
        ),
        "credential expiry",
    )
    .map_err(|detail| rejection(RejectionStage::CredentialTime, detail))?;
    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| rejection(RejectionStage::CredentialTime, "SD-JWT iat"))?;
    let nbf = claims
        .get("nbf")
        .and_then(Value::as_i64)
        .ok_or_else(|| rejection(RejectionStage::CredentialTime, "SD-JWT nbf"))?;
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(|| rejection(RejectionStage::CredentialTime, "SD-JWT exp"))?;
    let evaluation_time = valid_time(
        scenario
            .get("evaluationTime")
            .ok_or_else(|| rejection(RejectionStage::ContractValidation, "evaluation time"))?,
        "evaluation time",
    )
    .map_err(|detail| rejection(RejectionStage::CredentialTime, detail))?;
    let clock_skew = scenario
        .get("clockSkewSeconds")
        .and_then(Value::as_i64)
        .ok_or_else(|| rejection(RejectionStage::ContractValidation, "clock skew"))?;
    let issued_at = valid_time(
        &Value::String(
            map_text(authorization, "issuedAt")
                .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
                .into(),
        ),
        "authorization issuedAt",
    )
    .map_err(|detail| rejection(RejectionStage::CredentialTime, detail))?;
    if credential_expiry != share_expiry
        || map_text(credential, "expiresAt")
            .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
            != map_text(authorization, "shareExpiresAt")
                .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
        || iat > nbf
        || nbf >= exp
        || exp != share_expiry
        || iat != issued_at
        || nbf != issued_at
        || iat > evaluation_time + clock_skew
        || nbf > evaluation_time + clock_skew
        || exp <= evaluation_time - clock_skew
    {
        return Err(rejection(
            RejectionStage::CredentialTime,
            "credential time boundary failed",
        ));
    }
    Ok(())
}

fn verify_credential_candidate_signature(
    credential: &Map<String, Value>,
    claims: &Map<String, Value>,
    test_keys: &Value,
    mutation: &Map<String, Value>,
    kind: &str,
    issuer_key: &VerifyingKey,
) -> Result<bool> {
    // Prefer the candidate's declared public key.  This lets an alternate
    // test key authenticate the payload before issuer-key trust is evaluated.
    // The seed fallback keeps older checked-in vectors verifiable while they
    // migrate to the explicit public-key declaration.
    let candidates = if let Some(encoded) = mutation
        .get("candidateSigningPublicKeyByKind")
        .and_then(Value::as_object)
        .and_then(|keys| keys.get(kind))
    {
        let raw = b64_string(encoded, Some(32), "candidate signing public key")?;
        vec![
            VerifyingKey::from_bytes(&raw.try_into().map_err(|_| "candidate signing key length")?)
                .map_err(|error| error.to_string())?,
        ]
    } else {
        [
            "issuerSeedHex",
            "senderSeedHex",
            "holderSeedHex",
            "nodeSeedHex",
        ]
        .into_iter()
        .map(|name| seed_verifying_key(test_keys, name))
        .collect::<Result<Vec<_>>>()?
    };
    for candidate in candidates {
        if verify_sd_jwt_signature_prerequisites(credential, claims, &candidate).is_ok() {
            return Ok(candidate.to_bytes() == issuer_key.to_bytes());
        }
    }
    Err("credential signature does not verify under a declared test signing key".into())
}

fn validate_credential_candidate(
    scenario: &Value,
    test_keys: &Value,
    mutation: &Map<String, Value>,
    kind: &str,
    issuer_key: &VerifyingKey,
) -> std::result::Result<(), NegativeRejection> {
    let credential = object(scenario, "credential")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    let claims = map_object(credential, "claims")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    let candidate_uses_trusted_key = match verify_credential_candidate_signature(
        credential, claims, test_keys, mutation, kind, issuer_key,
    ) {
        Ok(value) => value,
        Err(_) => {
            return Err(rejection(
                RejectionStage::IssuerKey,
                "credential signature is not authentic under its declared key",
            ));
        }
    };
    validate_credential_semantic_boundaries(scenario)?;
    if !candidate_uses_trusted_key {
        return Err(rejection(
            RejectionStage::IssuerKey,
            "credential signature is not under the trusted issuer key",
        ));
    }
    validate_sd_jwt(scenario, issuer_key)
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))
}

fn validate_enrollment_boundary(scenario: &Value) -> std::result::Result<(), NegativeRejection> {
    let enrollment = object(scenario, "enrollment")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    if map_text(enrollment, "targetOrigin")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
        != "https://node.example"
        || map_text(enrollment, "nodeAudience")
            .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
            != "did:web:node.example"
    {
        return Err(rejection(
            RejectionStage::NodeAuthority,
            "enrollment authority binding failed",
        ));
    }
    if enrollment.get("enabled") != Some(&Value::Bool(true)) {
        return Err(rejection(
            RejectionStage::NodeEnrollment,
            "node enrollment is disabled",
        ));
    }
    if enrollment.get("keyVersion") != Some(&Value::from(1)) {
        return Err(rejection(
            RejectionStage::NodeKeyRetirement,
            "node enrollment key version is retired",
        ));
    }
    if map_text(enrollment, "invitationKid")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?
        != "did:web:node.example#invitation-key-1"
    {
        return Err(rejection(
            RejectionStage::NodeKeyRotation,
            "node enrollment key ID does not match its version",
        ));
    }
    Ok(())
}

fn validate_holder_signature_boundary(
    scenario: &Value,
    domains: &Map<String, Value>,
) -> std::result::Result<(), NegativeRejection> {
    let artifact = artifact_named(scenario, "holderBinding")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    let signature = object(artifact, "signature")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    let bytes = b64_map(signature, "value")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    assert_canonical_ed25519_s(&bytes)
        .map_err(|detail| rejection(RejectionStage::SignatureEncoding, detail))?;
    let enrollment = scenario
        .get("enrollment")
        .ok_or_else(|| rejection(RejectionStage::ContractValidation, "enrollment"))?;
    verify_signature_core(artifact, "holderBinding", enrollment)
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    verify_artifact(artifact, "holderBinding", domains, enrollment)
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))
}

fn validate_document_name_boundary(
    scenario: &Value,
    kind: &str,
    domains: &Map<String, Value>,
) -> std::result::Result<(), NegativeRejection> {
    let artifact = artifact_named(scenario, "inviteAuthorization")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    let enrollment = scenario
        .get("enrollment")
        .ok_or_else(|| rejection(RejectionStage::ContractValidation, "enrollment"))?;
    verify_artifact_with_schema(artifact, "inviteAuthorization", domains, enrollment, false)
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    let authorization = artifact
        .get("message")
        .ok_or_else(|| rejection(RejectionStage::ContractValidation, "authorization message"))?;
    let document_name = text(authorization, "documentName")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    if document_name.is_empty()
        || document_name.len() > 200
        || document_name
            .bytes()
            .any(|byte| byte <= 0x1f || byte == 0x7f)
    {
        return Err(rejection(
            RejectionStage::DocumentNameBytes,
            "document name byte boundary",
        ));
    }
    validate_message_schema("inviteAuthorization", authorization, kind)
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))
}

fn validate_cross_artifact_holder_boundary(
    scenario: &Value,
    domains: &Map<String, Value>,
) -> std::result::Result<(), NegativeRejection> {
    let artifact = artifact_named(scenario, "holderBinding")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    let holder = text(
        artifact
            .get("message")
            .ok_or_else(|| rejection(RejectionStage::ContractValidation, "holder message"))?,
        "holderDid",
    )
    .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    let raw = did_key_bytes(holder)
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    let key = VerifyingKey::from_bytes(&raw)
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail.to_string()))?;
    if key.is_weak() {
        return Err(rejection(
            RejectionStage::ContractValidation,
            "weak holder key",
        ));
    }
    let enrollment = scenario
        .get("enrollment")
        .ok_or_else(|| rejection(RejectionStage::ContractValidation, "enrollment"))?;
    verify_signature_core(artifact, "holderBinding", enrollment)
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    verify_artifact(artifact, "holderBinding", domains, enrollment)
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    validate_cross_artifact_holder(scenario)
        .map_err(|detail| rejection(RejectionStage::CrossArtifactHolder, detail))?;
    validate_cross_equations(scenario)
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))
}

fn artifact_named<'a>(scenario: &'a Value, name: &str) -> Result<&'a Value> {
    array(scenario, "artifacts")?
        .iter()
        .find(|artifact| text(artifact, "name").ok() == Some(name))
        .ok_or_else(|| format!("missing artifact {name}"))
}

fn assert_equal_field(
    left: &Map<String, Value>,
    right: &Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<()> {
    assert_ok(left.get(key) == right.get(key), label)
}

fn validate_share_url(url: &str, scenario: &Value) -> Result<()> {
    let cid = text(scenario, "shareCid")?;
    valid_cid(&Value::String(cid.into()), "share URL CID")?;
    let expected_prefix = format!("https://share.tinycloud.xyz/s/{cid}#");
    assert_ok(url.starts_with(&expected_prefix), "share URL origin/CID")?;
    let fragment = url
        .strip_prefix(&expected_prefix)
        .ok_or("share URL fragment")?;
    let members: Vec<&str> = fragment.split('&').collect();
    assert_ok(members.len() == 1, "share URL fragment fields")?;
    let (key, encoded) = members[0].split_once('=').ok_or("share URL key field")?;
    assert_ok(
        key == "k" && !encoded.is_empty() && !encoded.contains('='),
        "share URL key parser",
    )?;
    let key_bytes = b64_string(&Value::String(encoded.into()), Some(32), "share URL key")?;
    assert_ok(
        key_bytes == b64(scenario, "envelopeKey")?,
        "share URL key/envelope key binding",
    )?;
    Ok(())
}

fn validate_endpoint_body(
    name: &str,
    body: &Value,
    scenario: &Value,
    enrollment: &Value,
    issuer_key: &VerifyingKey,
) -> Result<()> {
    let kind = text(scenario, "kind")?;
    let source = scenario.get("source").ok_or("source")?;
    let source_object = source.as_object().ok_or("source object")?;
    let auth = object(scenario, "authorization")?;
    let credential = object(scenario, "credential")?;
    let artifacts = scenario.get("artifacts").ok_or("artifacts")?;
    match name {
        "authorizationRequest" => {
            let object = exact_object(
                body,
                &[
                    "jti",
                    "reportAbuseToken",
                    "senderDid",
                    "shareCid",
                    "shareId",
                    "delegationCid",
                    "authorityMaterialHandle",
                    "authorityMaterialDigest",
                    "policyCid",
                    "recipientEmail",
                    "targetOrigin",
                    "nodeAudience",
                    "documentName",
                    "senderTrust",
                    "contentSource",
                    "contentSourceDigest",
                    "shareExpiresAt",
                    "requestBodyDigest",
                ],
                &[],
                name,
            )?;
            for (key, expected) in [
                ("jti", map_text(auth, "jti")?),
                ("reportAbuseToken", text(scenario, "reportAbuseToken")?),
                ("senderDid", map_text(auth, "senderDid")?),
                ("shareCid", text(scenario, "shareCid")?),
                ("shareId", text(scenario, "shareId")?),
                ("delegationCid", text(scenario, "delegationCid")?),
                (
                    "authorityMaterialHandle",
                    text(scenario, "authorityMaterialHandle")?,
                ),
                (
                    "authorityMaterialDigest",
                    text(scenario, "authorityMaterialDigest")?,
                ),
                ("policyCid", text(scenario, "policyCid")?),
                ("recipientEmail", text(scenario, "canonicalEmail")?),
                ("targetOrigin", map_text(auth, "targetOrigin")?),
                ("nodeAudience", map_text(auth, "nodeAudience")?),
                ("documentName", map_text(auth, "documentName")?),
                ("senderTrust", map_text(auth, "senderTrust")?),
                ("shareExpiresAt", map_text(auth, "shareExpiresAt")?),
            ] {
                assert_ok(
                    map_text(object, key)? == expected,
                    "authorization request scope",
                )?;
            }
            assert_ok(
                map_text(object, "contentSourceDigest")? == text(scenario, "sourceDigest")?,
                "authorization request source digest",
            )?;
            validate_source(map_value(object, "contentSource", name)?, kind)?;
            let request_body = serde_json::json!({
                "shareCid": text(scenario, "shareCid")?,
                "shareId": text(scenario, "shareId")?,
                "policyCid": text(scenario, "policyCid")?,
                "delegationCid": text(scenario, "delegationCid")?,
                "authorityMaterialHandle": text(scenario, "authorityMaterialHandle")?,
                "authorityMaterialDigest": text(scenario, "authorityMaterialDigest")?,
                "recipientEmail": text(scenario, "canonicalEmail")?,
                "targetOrigin": map_text(auth, "targetOrigin")?,
                "nodeAudience": map_text(auth, "nodeAudience")?,
                "action": text(source, "action")?,
                "resource": text(source, "path")?,
            });
            assert_ok(
                digest(jcs(&request_body)?.as_bytes()) == map_text(object, "requestBodyDigest")?,
                "authorization request body digest",
            )?;
            valid_cid(
                map_value(object, "shareCid", name)?,
                "authorization request share CID",
            )?;
            valid_share_id(
                map_value(object, "shareId", name)?,
                "authorization request share ID",
            )?;
            valid_cid(
                map_value(object, "policyCid", name)?,
                "authorization request policy CID",
            )?;
            assert_ok(
                strict_email(map_text(object, "recipientEmail")?),
                "authorization request email",
            )?;
            valid_origin(
                map_value(object, "targetOrigin", name)?,
                "authorization request origin",
            )?;
            valid_did(
                map_value(object, "nodeAudience", name)?,
                "authorization request audience",
            )?;
            valid_time(
                map_value(object, "shareExpiresAt", name)?,
                "authorization share expiry",
            )?;
            assert_ok(
                map_text(object, "senderTrust")? == "verified"
                    || map_text(object, "senderTrust")? == "unverified",
                "authorization sender trust",
            )?;
            valid_digest(
                map_value(object, "contentSourceDigest", name)?,
                "authorization source digest",
            )?;
            valid_digest(
                map_value(object, "requestBodyDigest", name)?,
                "authorization request digest",
            )?;
        }
        "authorizationResponse" | "createInvitationRequest" => {
            let object = if name == "authorizationResponse" {
                exact_object(body, &["authorization", "proof"], &[], name)?
            } else {
                exact_object(body, &["authorization", "proof", "shareUrl"], &[], name)?
            };
            validate_invite_authorization(map_value(object, "authorization", name)?, kind)?;
            validate_proof(map_value(object, "proof", name)?, "authorization proof")?;
            let proof = map_object(object, "proof")?;
            let auth_artifact = artifact_named(scenario, "inviteAuthorization")?;
            proof_matches(
                &Value::Object(object.clone()),
                auth_artifact,
                enrollment,
                "authorization proof binding",
            )?;
            if name == "createInvitationRequest" {
                validate_share_url(map_text(object, "shareUrl")?, scenario)?;
                assert_ok(
                    map_text(proof, "kid")? == text(enrollment, "invitationKid")?,
                    "invitation proof kid",
                )?;
            }
        }
        "createInvitationResponse" | "resendResponse" => {
            let object = exact_object(
                body,
                &[
                    "status",
                    "retryAfterSeconds",
                    "delegationCid",
                    "authorityMaterialHandle",
                    "authorityMaterialDigest",
                ],
                &[],
                name,
            )?;
            const_string(
                map_value(object, "status", name)?,
                "accepted",
                "delivery status",
            )?;
            const_number(
                map_value(object, "retryAfterSeconds", name)?,
                20,
                "delivery retry",
            )?;
            valid_cid(
                map_value(object, "delegationCid", name)?,
                "delivery delegation CID",
            )?;
            assert_ok(
                map_text(object, "authorityMaterialHandle")?
                    == text(scenario, "authorityMaterialHandle")?,
                "delivery authority handle",
            )?;
            assert_ok(
                map_text(object, "authorityMaterialDigest")?
                    == text(scenario, "authorityMaterialDigest")?,
                "delivery authority digest",
            )?;
        }
        "resendRequest" => {
            let object = exact_object(body, &["invitationId", "claimSecret"], &[], name)?;
            b64_string(
                map_value(object, "invitationId", name)?,
                Some(16),
                "resend invitation ID",
            )?;
            b64_string(
                map_value(object, "claimSecret", name)?,
                Some(32),
                "resend claim secret",
            )?;
        }
        "activationRequest" => {
            let object = exact_object(body, &["invitationId", "claimSecret"], &[], name)?;
            b64_string(
                map_value(object, "invitationId", name)?,
                Some(16),
                "activation invitation ID",
            )?;
            b64_string(
                map_value(object, "claimSecret", name)?,
                Some(32),
                "activation claim secret",
            )?;
        }
        "activationResponse" => {
            let object = exact_object(
                body,
                &["status", "retryAfterSeconds", "activationId"],
                &[],
                name,
            )?;
            const_string(
                map_value(object, "status", name)?,
                "accepted",
                "activation status",
            )?;
            let retry = map_value(object, "retryAfterSeconds", name)?
                .as_i64()
                .ok_or("activation retry")?;
            assert_ok((0..=3600).contains(&retry), "activation retry range")?;
            b64_string(
                map_value(object, "activationId", name)?,
                Some(16),
                "activation ID",
            )?;
        }
        "claimChallengeMagicRequest" => {
            let object =
                exact_object(body, &["invitationId", "method", "activationId"], &[], name)?;
            b64_string(
                map_value(object, "invitationId", name)?,
                Some(16),
                "magic invitation ID",
            )?;
            const_string(map_value(object, "method", name)?, "magic", "magic method")?;
            b64_string(
                map_value(object, "activationId", name)?,
                Some(16),
                "magic activation ID",
            )?;
        }
        "claimChallengeOtpRequest" => {
            let object = exact_object(body, &["invitationId", "method", "otp"], &[], name)?;
            b64_string(
                map_value(object, "invitationId", name)?,
                Some(16),
                "OTP invitation ID",
            )?;
            const_string(map_value(object, "method", name)?, "otp", "OTP method")?;
            let otp = map_text(object, "otp")?;
            assert_ok(
                otp.len() == 6 && otp.bytes().all(|byte| byte.is_ascii_digit()),
                "OTP shape",
            )?;
        }
        "claimChallengeResponse" => {
            let object = exact_object(
                body,
                &[
                    "claimNonce",
                    "shareCid",
                    "shareId",
                    "policyCid",
                    "delegationCid",
                    "authorityMaterialHandle",
                    "authorityMaterialDigest",
                    "contentSource",
                    "contentSourceDigest",
                    "emailHash",
                    "targetOrigin",
                    "nodeAudience",
                    "expiresAt",
                ],
                &[],
                name,
            )?;
            b64_string(
                map_value(object, "claimNonce", name)?,
                Some(32),
                "claim nonce",
            )?;
            validate_source(map_value(object, "contentSource", name)?, kind)?;
            valid_digest(
                map_value(object, "contentSourceDigest", name)?,
                "claim source digest",
            )?;
            valid_digest(map_value(object, "emailHash", name)?, "claim email hash")?;
            valid_time(
                map_value(object, "expiresAt", name)?,
                "claim challenge expiry",
            )?;
            for key in ["shareCid", "policyCid"] {
                valid_cid(map_value(object, key, name)?, key)?;
            }
            valid_share_id(map_value(object, "shareId", name)?, "claim share ID")?;
            valid_cid(
                map_value(object, "delegationCid", name)?,
                "claim delegation CID",
            )?;
            assert_ok(
                map_text(object, "authorityMaterialHandle")?.starts_with("amh_"),
                "claim authority handle",
            )?;
            valid_digest(
                map_value(object, "authorityMaterialDigest", name)?,
                "claim authority digest",
            )?;
            valid_origin(map_value(object, "targetOrigin", name)?, "claim origin")?;
            valid_did(map_value(object, "nodeAudience", name)?, "claim audience")?;
        }
        "claimRedeemRequest" | "claimRedeemOtpRequest" => {
            let object = exact_object(
                body,
                &[
                    "version",
                    "redemptionId",
                    "invitationId",
                    "method",
                    "mailboxProof",
                    "binding",
                    "holderProof",
                ],
                &[],
                name,
            )?;
            const_string(
                map_value(object, "version", name)?,
                CONTRACT_VERSION,
                "redeem version",
            )?;
            b64_string(
                map_value(object, "redemptionId", name)?,
                Some(16),
                "redeem ID",
            )?;
            b64_string(
                map_value(object, "invitationId", name)?,
                Some(16),
                "redeem invitation ID",
            )?;
            let expected_method = if name == "claimRedeemRequest" {
                "magic"
            } else {
                "otp"
            };
            const_string(
                map_value(object, "method", name)?,
                expected_method,
                "redeem method",
            )?;
            if expected_method == "magic" {
                b64_string(
                    map_value(object, "mailboxProof", name)?,
                    Some(32),
                    "magic mailbox proof",
                )?;
            } else {
                let otp = map_text(object, "mailboxProof")?;
                assert_ok(
                    otp.len() == 6 && otp.bytes().all(|byte| byte.is_ascii_digit()),
                    "OTP mailbox proof",
                )?;
            }
            let binding = map_value(object, "binding", name)?;
            validate_holder_binding(binding, kind)?;
            let binding_object = binding.as_object().ok_or("binding object")?;
            assert_equal_field(
                object,
                binding_object,
                "redemptionId",
                "redeem/binding redemption ID",
            )?;
            assert_equal_field(
                object,
                binding_object,
                "invitationId",
                "redeem/binding invitation ID",
            )?;
            validate_proof(map_value(object, "holderProof", name)?, "holder proof")?;
            let holder_artifact = artifact_named(scenario, "holderBinding")?;
            let holder_proof = map_object(object, "holderProof")?;
            let holder_signature = holder_artifact
                .get("signature")
                .and_then(Value::as_object)
                .ok_or("holder artifact signature")?;
            assert_ok(
                map_text(holder_proof, "alg")? == "EdDSA"
                    && map_text(holder_proof, "kid")? == map_text(holder_signature, "kid")?
                    && map_text(holder_proof, "signature")? == map_text(holder_signature, "value")?,
                "holder wrapper proof binding",
            )?;
        }
        "claimRedeemResponse" => {
            let object = exact_object(
                body,
                &["format", "credential", "holderDid", "expiresAt"],
                &[],
                name,
            )?;
            const_string(
                map_value(object, "format", name)?,
                "vc+sd-jwt",
                "redeem response format",
            )?;
            assert_ok(
                map_text(object, "credential")? == map_text(credential, "credential")?,
                "redeem response credential",
            )?;
            assert_ok(
                map_text(object, "holderDid")? == map_text(credential, "holderDid")?,
                "redeem response holder",
            )?;
            assert_ok(
                map_text(object, "expiresAt")? == map_text(credential, "expiresAt")?,
                "redeem response expiry",
            )?;
            did_key_bytes(map_text(object, "holderDid")?)?;
        }
        "policyChallengeRequest" => {
            let object = exact_object(
                body,
                &[
                    "shareCid",
                    "shareId",
                    "delegationCid",
                    "policyCid",
                    "authorityMaterialHandle",
                    "authorityMaterialDigest",
                    "contentSource",
                    "contentSourceDigest",
                    "holderDid",
                    "targetOrigin",
                    "nodeAudience",
                    "action",
                    "resource",
                    "requestBodyDigest",
                ],
                &[],
                name,
            )?;
            validate_source(map_value(object, "contentSource", name)?, kind)?;
            for key in ["shareCid", "delegationCid", "policyCid"] {
                valid_cid(map_value(object, key, name)?, key)?;
            }
            assert_ok(
                map_text(object, "authorityMaterialHandle")?.starts_with("amh_"),
                "challenge authority handle",
            )?;
            valid_digest(
                map_value(object, "authorityMaterialDigest", name)?,
                "challenge authority digest",
            )?;
            valid_share_id(
                map_value(object, "shareId", name)?,
                "challenge request share ID",
            )?;
            did_key_bytes(map_text(object, "holderDid")?)?;
            valid_origin(
                map_value(object, "targetOrigin", name)?,
                "challenge request origin",
            )?;
            valid_did(
                map_value(object, "nodeAudience", name)?,
                "challenge request audience",
            )?;
            valid_path(
                map_value(object, "resource", name)?,
                "challenge request resource",
            )?;
            valid_digest(
                map_value(object, "contentSourceDigest", name)?,
                "challenge request source digest",
            )?;
            valid_digest(
                map_value(object, "requestBodyDigest", name)?,
                "challenge request body digest",
            )?;
        }
        "policyChallengeResponse" => {
            let object = exact_object(body, &["challenge", "proof"], &[], name)?;
            validate_message_schema(
                "policyChallenge",
                map_value(object, "challenge", name)?,
                kind,
            )?;
            validate_proof(map_value(object, "proof", name)?, "challenge proof")?;
            proof_matches(
                body,
                artifact_named(scenario, "policyChallenge")?,
                enrollment,
                "challenge proof binding",
            )?;
        }
        "policySessionRequest" => {
            let object = exact_object(body, &["presentation", "credential", "proof"], &[], name)?;
            validate_message_schema(
                "policyPresentation",
                map_value(object, "presentation", name)?,
                kind,
            )?;
            assert_ok(
                map_text(object, "credential")? == map_text(credential, "credential")?,
                "session credential binding",
            )?;
            validate_proof(map_value(object, "proof", name)?, "presentation proof")?;
            let proof = map_object(object, "proof")?;
            let artifact_signature = artifact_named(scenario, "policyPresentation")?
                .get("signature")
                .and_then(Value::as_object)
                .ok_or("presentation artifact signature")?;
            assert_ok(
                map_text(proof, "kid")? == map_text(artifact_signature, "kid")?
                    && map_text(proof, "signature")? == map_text(artifact_signature, "value")?,
                "presentation wrapper proof binding",
            )?;
        }
        "policySessionResponse" => {
            let object = exact_object(body, &["session", "proof"], &[], name)?;
            validate_message_schema("policySession", map_value(object, "session", name)?, kind)?;
            validate_proof(map_value(object, "proof", name)?, "session proof")?;
            proof_matches(
                body,
                artifact_named(scenario, "policySession")?,
                enrollment,
                "session proof binding",
            )?;
        }
        "kvReadRequest" | "sqlReadRequest" => {
            let object = exact_object(
                body,
                &[
                    "sessionId",
                    "delegationCid",
                    "authorityMaterialHandle",
                    "authorityMaterialDigest",
                    "contentSource",
                    "contentSourceDigest",
                    "action",
                    "resource",
                    "requestBodyDigest",
                    "invocation",
                    "proof",
                ],
                &[],
                name,
            )?;
            if (name == "kvReadRequest") != (kind == "kv") {
                return Ok(());
            }
            validate_source(map_value(object, "contentSource", name)?, kind)?;
            b64_string(
                map_value(object, "sessionId", name)?,
                Some(16),
                "read session ID",
            )?;
            valid_digest(
                map_value(object, "contentSourceDigest", name)?,
                "read source digest",
            )?;
            valid_path(map_value(object, "resource", name)?, "read resource")?;
            valid_digest(
                map_value(object, "requestBodyDigest", name)?,
                "read body digest",
            )?;
            valid_cid(
                map_value(object, "delegationCid", name)?,
                "read delegation CID",
            )?;
            assert_ok(
                map_text(object, "delegationCid")? == text(scenario, "delegationCid")?,
                "read delegation binding",
            )?;
            assert_ok(
                map_text(object, "authorityMaterialHandle")?
                    == text(scenario, "authorityMaterialHandle")?,
                "read authority handle binding",
            )?;
            assert_ok(
                map_text(object, "authorityMaterialDigest")?
                    == text(scenario, "authorityMaterialDigest")?,
                "read authority digest binding",
            )?;
            validate_message_schema(
                "readInvocation",
                map_value(object, "invocation", name)?,
                kind,
            )?;
            validate_proof(map_value(object, "proof", name)?, "read proof")?;
            let invocation = map_object(object, "invocation")?;
            assert_equal_field(object, invocation, "sessionId", "read/invocation session")?;
            assert_equal_field(
                object,
                invocation,
                "delegationCid",
                "read/invocation delegation",
            )?;
            assert_equal_field(
                object,
                invocation,
                "authorityMaterialHandle",
                "read/invocation authority handle",
            )?;
            assert_equal_field(
                object,
                invocation,
                "authorityMaterialDigest",
                "read/invocation authority digest",
            )?;
            assert_equal_field(
                object,
                invocation,
                "contentSource",
                "read/invocation source",
            )?;
            assert_equal_field(
                object,
                invocation,
                "contentSourceDigest",
                "read/invocation source digest",
            )?;
            assert_equal_field(object, invocation, "action", "read/invocation action")?;
            assert_equal_field(object, invocation, "resource", "read/invocation resource")?;
            assert_equal_field(
                object,
                invocation,
                "requestBodyDigest",
                "read/invocation body digest",
            )?;
            let proof = map_object(object, "proof")?;
            let signature = artifact_named(scenario, "readInvocation")?
                .get("signature")
                .and_then(Value::as_object)
                .ok_or("read artifact signature")?;
            assert_ok(
                map_text(proof, "kid")? == map_text(signature, "kid")?
                    && map_text(proof, "signature")? == map_text(signature, "value")?,
                "read wrapper proof binding",
            )?;
            let mut preimage = object.clone();
            preimage.remove("proof");
            preimage.remove("requestBodyDigest");
            if let Some(invocation) = preimage
                .get_mut("invocation")
                .and_then(Value::as_object_mut)
            {
                invocation.remove("requestBodyDigest");
            }
            assert_ok(
                digest(jcs(&Value::Object(preimage))?.as_bytes())
                    == map_text(object, "requestBodyDigest")?,
                "read request body digest preimage",
            )?;
        }
        "readResponse" => {
            let object = exact_object(
                body,
                &[
                    "type",
                    "version",
                    "sessionId",
                    "requestJti",
                    "readJti",
                    "audience",
                    "holderDid",
                    "credentialDigest",
                    "issuedAt",
                    "expiresAt",
                    "mediaType",
                    "content",
                    "contentSource",
                    "contentSourceDigest",
                    "action",
                    "resource",
                    "requestBodyDigest",
                    "bodyDigest",
                    "delegationCid",
                    "authorityMaterialHandle",
                    "authorityMaterialDigest",
                    "proof",
                ],
                &[],
                name,
            )?;
            const_string(
                map_value(object, "type", name)?,
                "TinyCloudShareReadResponse",
                "read response type",
            )?;
            const_number(
                map_value(object, "version", name)?,
                1,
                "read response version",
            )?;
            b64_string(
                map_value(object, "sessionId", name)?,
                Some(16),
                "read response session",
            )?;
            b64_string(
                map_value(object, "requestJti", name)?,
                Some(16),
                "read response request JTI",
            )?;
            b64_string(
                map_value(object, "readJti", name)?,
                Some(16),
                "read response read JTI",
            )?;
            assert_ok(
                map_text(object, "requestJti")? == map_text(object, "readJti")?,
                "read JTI binding",
            )?;
            assert_ok(
                map_text(object, "audience")? == map_text(auth, "nodeAudience")?,
                "read response audience",
            )?;
            did_key_bytes(map_text(object, "holderDid")?)?;
            valid_digest(
                map_value(object, "credentialDigest", name)?,
                "read credential digest",
            )?;
            valid_time(
                map_value(object, "issuedAt", name)?,
                "read response issuedAt",
            )?;
            valid_time(
                map_value(object, "expiresAt", name)?,
                "read response expiresAt",
            )?;
            const_string(
                map_value(object, "mediaType", name)?,
                "text/markdown; charset=utf-8",
                "read media type",
            )?;
            let content = map_text(object, "content")?;
            assert_ok(content.len() <= 1_048_576, "read content byte limit")?;
            assert_ok(
                map_text(object, "contentSourceDigest")? == text(scenario, "sourceDigest")?,
                "read response source",
            )?;
            validate_source(map_value(object, "contentSource", name)?, kind)?;
            assert_ok(
                map_text(object, "action")? == text(source, "action")?,
                "read response action",
            )?;
            assert_ok(
                map_text(object, "resource")? == text(source, "path")?,
                "read response resource",
            )?;
            valid_digest(
                map_value(object, "contentSourceDigest", name)?,
                "read response source digest",
            )?;
            valid_digest(
                map_value(object, "requestBodyDigest", name)?,
                "read response request digest",
            )?;
            assert_ok(
                digest(content.as_bytes()) == map_text(object, "bodyDigest")?,
                "read response body digest",
            )?;
            valid_digest(
                map_value(object, "bodyDigest", name)?,
                "read response body digest shape",
            )?;
            valid_cid(
                map_value(object, "delegationCid", name)?,
                "read delegation CID",
            )?;
            assert_ok(
                map_text(object, "authorityMaterialHandle")?
                    == text(scenario, "authorityMaterialHandle")?,
                "read authority handle",
            )?;
            assert_ok(
                map_text(object, "authorityMaterialDigest")?
                    == text(scenario, "authorityMaterialDigest")?,
                "read authority digest",
            )?;
            validate_proof(map_value(object, "proof", name)?, "read response proof")?;
            let proof = map_object(object, "proof")?;
            assert_ok(
                map_text(proof, "kid")? == text(enrollment, "invitationKid")?,
                "read response proof kid",
            )?;
            let signature = URL_SAFE_NO_PAD
                .decode(map_text(proof, "signature")?)
                .map_err(|e| e.to_string())?;
            let public: [u8; 32] = b64(enrollment, "invitationPublicKey")?
                .try_into()
                .map_err(|_| "node public key length".to_string())?;
            let key = VerifyingKey::from_bytes(&public).map_err(|e| e.to_string())?;
            let sig = Signature::from_slice(&signature).map_err(|e| e.to_string())?;
            let body_without_proof = {
                let mut copy = object.clone();
                copy.remove("proof");
                Value::Object(copy)
            };
            let domain = "xyz.tinycloud.share/read-response/v1\0";
            let signed = [domain.as_bytes(), jcs(&body_without_proof)?.as_bytes()].concat();
            key.verify_strict(&signed, &sig)
                .map_err(|e| format!("read response proof: {e}"))?;
        }
        value if value.ends_with("Failure") => {
            let object = exact_object(body, &["error"], &[], name)?;
            let error = exact_object(
                map_value(object, "error", name)?,
                &["code"],
                &[],
                "failure error",
            )?;
            let code = map_text(error, "code")?;
            assert_ok(
                [
                    "invalid_or_expired_claim",
                    "claim_already_used",
                    "invitation_authorization_invalid",
                    "untrusted_node",
                    "invalid_content_source",
                    "invalid_holder_proof",
                    "invalid_credential_profile",
                    "policy_denied",
                    "nonce_already_used",
                    "read_denied",
                    "capability_unavailable",
                ]
                .contains(&code),
                "failure code",
            )?;
        }
        _ => return Err(format!("unknown endpoint preimage {name}")),
    }
    let _ = (source_object, artifacts, issuer_key);
    Ok(())
}

fn validate_jti_replay_bindings(scenario: &Value) -> Result<()> {
    let mut seen = HashSet::new();
    for (artifact_name, field) in [
        ("inviteAuthorization", "jti"),
        ("holderBinding", "jti"),
        ("policyPresentation", "jti"),
        ("readInvocation", "jti"),
    ] {
        let jti = text(artifact_message(scenario, artifact_name)?, field)?;
        assert_ok(seen.insert(jti.to_string()), "duplicate artifact JTI")?;
    }
    let credential_jti = map_text(
        map_object(object(scenario, "credential")?, "claims")?,
        "jti",
    )?;
    assert_ok(
        seen.insert(credential_jti.to_string()),
        "credential JTI replay",
    )?;
    Ok(())
}
fn validate_negative(negative: &Value) -> Result<()> {
    let rows = array(negative, "cases")?;
    let known = [
        "email",
        "cid",
        "policy",
        "aead",
        "schema",
        "envelope",
        "signature",
        "jcs",
        "encoding",
        "did-key",
        "source",
        "binding",
        "credential",
        "state",
        "capability",
        "preimage",
        "method",
        "proof",
        "sd-jwt",
        "share-url",
        "enrollment",
        "authority",
    ];
    let mut ids = Vec::new();
    for row in rows {
        let id = text(row, "id")?;
        assert_ok(
            !ids.iter().any(|seen| seen == id),
            "negative IDs must be unique",
        )?;
        ids.push(id.to_string());
        assert_ok(
            text(row, "expected")? == "reject",
            "negative expected result",
        )?;
        let kind = text(row, "kind")?;
        assert_ok(known.contains(&kind), "unknown negative kind")?;
        assert_ok(
            !text(row, "target")?.is_empty() && !text(row, "mutation")?.is_empty(),
            "negative target/mutation",
        )?;
        assert_ok(
            !text(row, "rejectionStage")?.is_empty(),
            "negative rejection stage",
        )?;
        let mutation = object(row, "mutationData")?;
        assert_ok(
            mutation.get("operation").and_then(Value::as_str).is_some(),
            "negative mutation operation",
        )?;
        let applies = array(row, "appliesTo")?;
        assert_ok(
            !applies.is_empty()
                && applies
                    .iter()
                    .all(|value| matches!(value.as_str(), Some("kv") | Some("sql"))),
            "negative applicability",
        )?;
        if kind == "email" {
            assert_ok(text(row, "input").is_ok(), "email negative input")?;
        }
        if kind == "method" {
            assert_ok(
                mutation.get("method").and_then(Value::as_str).is_some()
                    && mutation.get("field").and_then(Value::as_str).is_some()
                    && mutation.get("value").and_then(Value::as_str).is_some(),
                "method negative mutation",
            )?;
        }
        if kind == "jcs" && id.starts_with("jcs-") {
            assert_ok(
                mutation
                    .get("jsonLiteral")
                    .and_then(Value::as_str)
                    .is_some(),
                "number negative literal",
            )?;
        }
        match id {
            "jcs-fractional-number" => assert_ok(
                mutation.get("numberKind").and_then(Value::as_str) == Some("fractional")
                    && mutation.get("jsonLiteral").and_then(Value::as_str) == Some("1.5"),
                "fractional negative",
            )?,
            "jcs-negative-zero" => assert_ok(
                mutation.get("numberKind").and_then(Value::as_str) == Some("negative-zero")
                    && mutation.get("jsonLiteral").and_then(Value::as_str) == Some("-0"),
                "negative-zero negative",
            )?,
            "jcs-unsafe-number" => assert_ok(
                mutation.get("numberKind").and_then(Value::as_str) == Some("unsafe-integer")
                    && mutation.get("jsonLiteral").and_then(Value::as_str)
                        == Some("9007199254740992"),
                "unsafe integer negative",
            )?,
            "claim-redeem-magic-with-otp" => assert_ok(
                mutation.get("method").and_then(Value::as_str) == Some("magic")
                    && mutation.get("value").and_then(Value::as_str) == Some("042731"),
                "magic/otp negative",
            )?,
            "claim-redeem-otp-with-magic" => assert_ok(
                mutation.get("method").and_then(Value::as_str) == Some("otp")
                    && mutation.get("value").and_then(Value::as_str)
                        == Some("ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"),
                "otp/magic negative",
            )?,
            "sd-jwt-missing-alg" => assert_ok(
                kind == "sd-jwt"
                    && mutation.get("operation").and_then(Value::as_str) == Some("delete")
                    && mutation.get("expected").and_then(Value::as_str) == Some("sha-256"),
                "SD-JWT algorithm negative",
            )?,
            "sd-jwt-two-element-disclosure" => assert_ok(
                kind == "sd-jwt"
                    && mutation
                        .get("arrayShape")
                        .and_then(Value::as_array)
                        .is_some_and(|values| values.len() == 2),
                "SD-JWT disclosure shape negative",
            )?,
            "policy-challenge-response-proof" | "policy-session-response-proof" => {
                assert_ok(kind == "proof", "proof negative dispatch")?
            }
            _ => {}
        }
    }
    assert_ok(rows.len() >= 27, "negative matrix too small")
}
fn artifact_message<'a>(scenario: &'a Value, name: &str) -> Result<&'a Value> {
    array(scenario, "artifacts")?
        .iter()
        .find(|artifact| text(artifact, "name").ok() == Some(name))
        .and_then(|artifact| artifact.get("message"))
        .ok_or_else(|| format!("missing artifact message {name}"))
}
fn check_scope(value: &Value, expected: &Map<String, Value>, source: &Value) -> Result<()> {
    for (field, wanted) in expected {
        if let Some(actual) = value.get(field) {
            assert_ok(actual == wanted, &format!("{field} equation"))?;
        }
    }
    if let Some(actual) = value.get("contentSource") {
        assert_ok(jcs(actual)? == jcs(source)?, "content source equation")?;
    }
    if let Some(actual) = value.get("contentSourceDigest") {
        assert_ok(
            actual == &Value::String(digest(jcs(source)?.as_bytes())),
            "content source digest equation",
        )?;
    }
    Ok(())
}
fn validate_cross_equations(scenario: &Value) -> Result<()> {
    let policy = scenario.get("policy").ok_or("policy")?;
    let authorization = scenario.get("authorization").ok_or("authorization")?;
    let binding = artifact_message(scenario, "holderBinding")?;
    let canonical = text(scenario, "canonicalEmail")?;
    assert_ok(
        text(policy, "recipientEmail")? == text(authorization, "recipientEmail")?
            && text(authorization, "recipientEmail")? == canonical,
        "canonical email equation",
    )?;
    let credential = scenario.get("credential").ok_or("credential")?;
    let disclosure = array(credential, "disclosures")?
        .first()
        .ok_or("disclosure")?;
    assert_ok(
        text(disclosure, "path")? == "/email" && text(disclosure, "value")? == canonical,
        "disclosed email equation",
    )?;
    let preimages = object(scenario, "preimages")?;
    for name in ["claimRedeemRequest", "claimRedeemOtpRequest"] {
        let body = object(preimages.get(name).ok_or("redeem preimage")?, "body")?;
        assert_ok(
            map_text(body, "redemptionId")? == text(binding, "redemptionId")?
                && map_text(body, "invitationId")? == text(binding, "invitationId")?,
            "redeem identifier equation",
        )?;
    }
    let source = scenario.get("source").ok_or("source")?;
    let mut expected = Map::new();
    for field in ["shareCid", "shareId", "policyCid"] {
        expected.insert(field.into(), text(scenario, field)?.into());
    }
    expected.insert(
        "delegationCid".into(),
        text(scenario, "delegationCid")?.into(),
    );
    expected.insert(
        "authorityMaterialHandle".into(),
        text(scenario, "authorityMaterialHandle")?.into(),
    );
    expected.insert(
        "authorityMaterialDigest".into(),
        text(scenario, "authorityMaterialDigest")?.into(),
    );
    expected.insert(
        "targetOrigin".into(),
        text(authorization, "targetOrigin")?.into(),
    );
    expected.insert(
        "nodeAudience".into(),
        text(authorization, "nodeAudience")?.into(),
    );
    expected.insert("holderDid".into(), text(binding, "holderDid")?.into());
    expected.insert(
        "contentSourceDigest".into(),
        text(scenario, "sourceDigest")?.into(),
    );
    expected.insert("action".into(), text(source, "action")?.into());
    expected.insert("resource".into(), text(source, "path")?.into());
    for artifact in array(scenario, "artifacts")? {
        check_scope(
            artifact.get("message").ok_or("artifact message")?,
            &expected,
            source,
        )?;
    }
    let authority = artifact_message(scenario, "authorityMaterial")?;
    let authority_object = authority.as_object().ok_or("authority material object")?;
    let authority_mapping = authority_object
        .get("mapping")
        .and_then(Value::as_object)
        .ok_or("authority material mapping")?;
    assert_ok(
        map_text(authority_mapping, "sharePolicyCid")? == text(scenario, "policyCid")?
            && map_text(authority_mapping, "shareDelegationCid")?
                == text(scenario, "delegationCid")?
            && map_text(authority_object, "handle")? == text(scenario, "authorityMaterialHandle")?,
        "authority material identifier equation",
    )?;
    let envelope = scenario.get("envelope").ok_or("envelope")?;
    assert_ok(
        text(envelope, "shareId")? == text(scenario, "shareId")?,
        "envelope share ID equation",
    )?;
    let target = object(envelope, "target")?;
    assert_ok(
        map_text(object(envelope, "authorizationTarget")?, "policyCid")?
            == text(scenario, "policyCid")?
            && map_text(target, "origin")? == expected["targetOrigin"].as_str().unwrap_or("")
            && map_text(target, "nodeAudience")? == expected["nodeAudience"].as_str().unwrap_or("")
            && map_text(map_object(target, "resource")?, "path")?
                == expected["resource"].as_str().unwrap_or(""),
        "envelope scope equation",
    )?;
    let enrollment = scenario.get("enrollment").ok_or("enrollment")?;
    assert_ok(
        text(enrollment, "targetOrigin")? == expected["targetOrigin"]
            && text(enrollment, "nodeAudience")? == expected["nodeAudience"],
        "enrollment equation",
    )?;
    for preimage in preimages.values() {
        let body = preimage.get("body").ok_or("preimage body")?;
        check_scope(body, &expected, source)?;
        for nested in [
            "authorization",
            "binding",
            "challenge",
            "presentation",
            "session",
            "invocation",
        ] {
            if let Some(value) = body.get(nested) {
                check_scope(value, &expected, source)?;
            }
        }
    }
    let claims = object(credential, "claims")?;
    let share = map_object(claims, "tinycloud_share")?;
    assert_ok(
        map_text(share, "share_cid")? == text(scenario, "shareCid")?
            && map_text(share, "share_id")? == text(scenario, "shareId")?
            && map_text(share, "policy_cid")? == text(scenario, "policyCid")?
            && map_text(share, "node_audience")? == expected["nodeAudience"].as_str().unwrap_or(""),
        "credential scope equation",
    )?;
    Ok(())
}

fn validate_cross_artifact_holder(scenario: &Value) -> Result<()> {
    let holder = text(artifact_message(scenario, "holderBinding")?, "holderDid")?;
    assert_ok(
        text(
            artifact_message(scenario, "policyPresentation")?,
            "holderDid",
        )? == holder
            && text(artifact_message(scenario, "readInvocation")?, "holderDid")? == holder
            && map_text(object(scenario, "credential")?, "holderDid")? == holder
            && map_text(
                map_object(object(scenario, "credential")?, "claims")?,
                "sub",
            )? == holder,
        "cross-artifact-holder",
    )
}
fn strict_email(input: &str) -> bool {
    if !input.is_ascii()
        || input.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
        || input.matches('@').count() != 1
    {
        return false;
    }
    let (local, domain) = input.split_once('@').unwrap_or(("", ""));
    if local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.len() > 253
        || input.len() > 254
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
    {
        return false;
    }
    let atext = |byte: u8| byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte);
    if !local
        .split('.')
        .all(|part| !part.is_empty() && part.bytes().all(atext))
    {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}
fn validate_sql_arguments(source: &Value) -> Result<()> {
    if text(source, "kind")? != "sql" {
        return Ok(());
    }
    let arguments = object(source, "arguments")?;
    assert_ok(arguments.len() <= 32, "SQL arguments property limit")?;
    for value in arguments.values() {
        let safe_integer = value
            .as_i64()
            .is_some_and(|number| number.unsigned_abs() <= 9_007_199_254_740_991)
            || value
                .as_u64()
                .is_some_and(|number| number <= 9_007_199_254_740_991);
        assert_ok(safe_integer, "SQL argument must be a safe integer")?;
    }
    let canonical = jcs(&Value::Object(arguments.clone()))?;
    assert_ok(canonical.len() <= 4096, "SQL arguments byte limit")?;
    assert_ok(
        digest(canonical.as_bytes()) == text(source, "argumentsDigest")?,
        "SQL arguments digest mismatch",
    )
}
fn validate_scanner_fragment(url: &str, scenario: &Value) -> Result<()> {
    let (base, fragment) = url.split_once('#').ok_or("scanner fragment missing")?;
    assert_ok(
        base == format!(
            "https://share.tinycloud.xyz/s/{}",
            text(scenario, "shareCid")?
        ),
        "scanner share URL",
    )?;
    let mut fields = Map::new();
    for member in fragment.split('&') {
        let (key, value) = member.split_once('=').ok_or("scanner fragment member")?;
        assert_ok(
            matches!(key, "k" | "i" | "c") && !fields.contains_key(key),
            "scanner fragment shape",
        )?;
        fields.insert(key.into(), Value::String(value.into()));
    }
    assert_ok(fields.len() == 3, "scanner fragment cardinality")?;
    for (key, length) in [("k", 32usize), ("i", 16usize), ("c", 32usize)] {
        let encoded = map_text(&fields, key)?;
        let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|e| e.to_string())?;
        assert_ok(
            decoded.len() == length && URL_SAFE_NO_PAD.encode(&decoded) == encoded,
            "scanner fragment encoding",
        )?;
    }
    Ok(())
}

fn rejection(stage: RejectionStage, detail: impl Into<String>) -> NegativeRejection {
    NegativeRejection {
        stage,
        detail: detail.into(),
    }
}

fn validate_share_url_boundary(
    url: &str,
    scenario: &Value,
) -> std::result::Result<(), NegativeRejection> {
    let cid = text(scenario, "shareCid")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(rejection(
            RejectionStage::ShareUrlScheme,
            "share URL must use HTTPS",
        ));
    };
    let (authority, path_and_fragment) = rest
        .split_once('/')
        .ok_or_else(|| rejection(RejectionStage::ShareUrlOrigin, "share URL origin missing"))?;
    if authority.contains('@') {
        return Err(rejection(
            RejectionStage::ShareUrlOrigin,
            "share URL userinfo is forbidden",
        ));
    }
    if authority.strip_prefix("share.tinycloud.xyz:").is_some() {
        return Err(rejection(
            RejectionStage::ShareUrlPort,
            "share URL explicit port is forbidden",
        ));
    }
    if authority != "share.tinycloud.xyz" {
        return Err(rejection(
            RejectionStage::ShareUrlOrigin,
            "share URL origin mismatch",
        ));
    }
    let fragment_start = path_and_fragment.find('#');
    let path_end = fragment_start.unwrap_or(path_and_fragment.len());
    if path_and_fragment[..path_end].contains('?') {
        return Err(rejection(
            RejectionStage::ShareUrlQuery,
            "share URL query is forbidden",
        ));
    }
    let Some(fragment_start) = fragment_start else {
        return Err(rejection(
            RejectionStage::ShareUrlFragment,
            "share URL fragment missing",
        ));
    };
    let path = &path_and_fragment[..fragment_start];
    let fragment = &path_and_fragment[fragment_start + 1..];
    if path != format!("s/{cid}") {
        return Err(rejection(
            RejectionStage::ShareUrlPath,
            "share URL path mismatch",
        ));
    }
    let members: Vec<&str> = fragment.split('&').collect();
    if members.len() != 1 {
        return Err(rejection(
            RejectionStage::ShareUrlFragment,
            "share URL fragment fields",
        ));
    }
    let Some((key, encoded)) = members[0].split_once('=') else {
        return Err(rejection(
            RejectionStage::ShareUrlFragment,
            "share URL key field",
        ));
    };
    if key != "k" || encoded.is_empty() || encoded.contains('=') {
        return Err(rejection(
            RejectionStage::ShareUrlFragment,
            "share URL fragment key",
        ));
    }
    if encoded.contains('%') {
        return Err(rejection(
            RejectionStage::ShareUrlFragmentEncoding,
            "share URL fragment percent encoding",
        ));
    }
    let key_bytes = b64_string(&Value::String(encoded.into()), Some(32), "share URL key")
        .map_err(|detail| rejection(RejectionStage::ShareUrlKey, detail))?;
    let envelope_key = b64(scenario, "envelopeKey")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    if key_bytes != envelope_key {
        return Err(rejection(
            RejectionStage::ContractValidation,
            "share URL key binding",
        ));
    }
    Ok(())
}

fn validate_scanner_fragment_boundary(
    url: &str,
    scenario: &Value,
) -> std::result::Result<(), NegativeRejection> {
    if url.contains('%') {
        return Err(rejection(
            RejectionStage::ScannerFragmentEncoding,
            "scanner fragment percent encoding",
        ));
    }
    validate_scanner_fragment(url, scenario)
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))
}

fn artifact_message_mut<'a>(
    scenario: &'a mut Value,
    name: &str,
) -> Result<&'a mut Map<String, Value>> {
    scenario
        .get_mut("artifacts")
        .and_then(Value::as_array_mut)
        .and_then(|artifacts| {
            artifacts
                .iter_mut()
                .find(|artifact| text(artifact, "name").ok() == Some(name))
        })
        .and_then(|artifact| artifact.get_mut("message"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("missing mutable artifact message {name}"))
}
fn artifact_mut<'a>(scenario: &'a mut Value, name: &str) -> Result<&'a mut Map<String, Value>> {
    scenario
        .get_mut("artifacts")
        .and_then(Value::as_array_mut)
        .and_then(|artifacts| {
            artifacts
                .iter_mut()
                .find(|artifact| text(artifact, "name").ok() == Some(name))
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("missing mutable artifact {name}"))
}
fn preimage_body_mut<'a>(
    scenario: &'a mut Value,
    name: &str,
) -> Result<&'a mut Map<String, Value>> {
    scenario
        .get_mut("preimages")
        .and_then(Value::as_object_mut)
        .and_then(|preimages| preimages.get_mut(name))
        .and_then(|preimage| preimage.get_mut("body"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("missing mutable preimage body {name}"))
}
fn mutation_value<'a>(mutation: &'a Map<String, Value>, kind: &str) -> Option<&'a Value> {
    mutation
        .get("valueByKind")
        .and_then(|values| values.get(kind))
        .or_else(|| mutation.get("value"))
}
fn known_native_id(id: &str) -> bool {
    matches!(
        id,
        "leading-space"
            | "trailing-space"
            | "tab"
            | "newline"
            | "inner-space"
            | "leading-dot-local"
            | "trailing-dot-local"
            | "repeated-dot-local"
            | "empty-local"
            | "empty-domain"
            | "multiple-at"
            | "quoted-local"
            | "comment-local"
            | "backslash-local"
            | "angle-form"
            | "unicode-local"
            | "unicode-domain"
            | "local-over-64"
            | "label-over-63"
            | "empty-domain-label"
            | "trailing-domain-dot"
            | "leading-hyphen"
            | "trailing-hyphen"
            | "domain-over-253"
            | "total-over-254"
            | "policy-cid-is-real"
            | "policy-bytes-self-policy-cid"
            | "share-cid-is-real"
            | "sealed-blob-aead-tamper"
            | "envelope-policy-target-missing-kind"
            | "envelope-policy-target-missing-bytes"
            | "envelope-policy-target-mismatch"
            | "envelope-origin-mismatch"
            | "share-url-userinfo"
            | "share-url-query"
            | "share-url-query-missing-fragment"
            | "share-url-duplicate-k"
            | "share-url-unknown-fragment"
            | "share-url-noncanonical-k"
            | "share-url-wrong-origin"
            | "share-url-wrong-path"
            | "share-url-http-scheme"
            | "share-url-explicit-port"
            | "share-url-percent-encoded-fragment"
            | "document-name-over-200-utf8"
            | "authorization-recipient-email-mismatch"
            | "redeem-redemption-id-mismatch"
            | "redeem-invitation-id-mismatch"
            | "share-id-propagation"
            | "share-cid-propagation"
            | "policy-cid-propagation"
            | "target-origin-propagation"
            | "node-audience-propagation"
            | "holder-did-propagation"
            | "content-source-digest-propagation"
            | "action-propagation"
            | "resource-propagation"
            | "envelope-domain-from-unregistered-label"
            | "jcs-lone-surrogate"
            | "jcs-unsafe-number"
            | "jcs-fractional-number"
            | "jcs-negative-zero"
            | "jcs-undefined"
            | "noncanonical-b64url-16-tail"
            | "noncanonical-b64url-64-tail"
            | "noncanonical-holder-kid"
            | "small-order-did-key"
            | "noncanonical-ed25519-s"
            | "short-signature"
            | "wrong-source-digest"
            | "sql-string-argument"
            | "sql-fractional-argument"
            | "sql-negative-zero-argument"
            | "sql-arguments-too-large"
            | "sql-arbitrary-query-field"
            | "policy-action-source-mismatch"
            | "content-source-propagation"
            | "credential-sub-mismatch"
            | "credential-legacy-email-path"
            | "credential-unsupported-status"
            | "credential-expired-resigned"
            | "credential-expiry-boundary-resigned"
            | "credential-issuer-did-resigned"
            | "credential-issuer-key-resigned"
            | "credential-vct-resigned"
            | "credential-holder-resigned"
            | "credential-scope-resigned"
            | "different-holder-valid-signature"
            | "policy-challenge-replay"
            | "session-token-only"
            | "old-secret-after-resend"
            | "otp-after-five-wrong"
            | "scanner-get"
            | "scanner-fragment-percent-encoded"
            | "resend-recipient-supplied-email"
            | "capability-extra-route"
            | "capability-wildcard-origin"
            | "node-enrollment-disabled"
            | "node-enrollment-origin-audience"
            | "node-enrollment-audience-origin"
            | "node-enrollment-retired-key"
            | "node-enrollment-kid-version-mismatch"
            | "read-body-one-field-mutation"
            | "claim-redeem-magic-with-otp"
            | "claim-redeem-otp-with-magic"
            | "policy-challenge-response-proof"
            | "policy-session-response-proof"
            | "authority-material-signature"
            | "authority-material-policy-mapping"
            | "authority-status-rollback"
            | "authority-status-stale"
            | "authority-status-revoked"
            | "authority-key-version"
            | "authority-attestation-binding"
            | "authority-measurement-digest-expiry"
            | "authority-identifier-domain-confusion"
            | "sd-jwt-missing-alg"
            | "sd-jwt-two-element-disclosure"
    )
}
fn apply_negative_mutation(
    scenario: &mut Value,
    states: &mut Value,
    row: &Value,
    kind: &str,
) -> Result<()> {
    let target = text(row, "target")?;
    let mutation = object(row, "mutationData")?;
    let value = mutation_value(mutation, kind).cloned();
    match target {
        "canonicalEmail" => {
            scenario["canonicalEmail"] = Value::String(map_text(mutation, "input")?.into());
        }
        "policyBytes" => match mutation.get("operation").and_then(Value::as_str) {
            Some("replace") => {
                let replacement = map_text(mutation, "replacement")?;
                scenario["policyBytes"] = Value::String(URL_SAFE_NO_PAD.encode(replacement));
            }
            Some("insert-property") => {
                let mut policy = object(scenario, "policy")?.clone();
                policy.insert(
                    map_text(mutation, "property")?.into(),
                    mutation
                        .get("value")
                        .cloned()
                        .ok_or("policy property value")?,
                );
                let bytes = jcs(&Value::Object(policy))?.into_bytes();
                scenario["policyBytes"] = Value::String(URL_SAFE_NO_PAD.encode(bytes));
            }
            _ => return Err(format!("unsupported policyBytes mutation {target}")),
        },
        "sealedBlob" => {
            let mut blob = b64(scenario, "sealedBlob")?;
            let last = blob.last_mut().ok_or("empty sealed blob")?;
            *last ^= 1;
            scenario["sealedBlob"] = Value::String(URL_SAFE_NO_PAD.encode(blob));
        }
        "envelope.authorizationTarget.kind" | "envelope.authorizationTarget.policyBytes" => {
            let target = scenario
                .get_mut("envelope")
                .and_then(Value::as_object_mut)
                .and_then(|envelope| envelope.get_mut("authorizationTarget"))
                .and_then(Value::as_object_mut)
                .ok_or("authorization target")?;
            let field = text(row, "target")?
                .rsplit('.')
                .next()
                .ok_or("authorization target field")?;
            target.remove(field);
        }
        "envelope.authorizationTarget" => {
            let target = scenario
                .get_mut("envelope")
                .and_then(Value::as_object_mut)
                .and_then(|envelope| envelope.get_mut("authorizationTarget"))
                .and_then(Value::as_object_mut)
                .ok_or("authorization target")?;
            target.insert("kind".into(), Value::String("policy".into()));
            target.insert("policyCid".into(), map_text(mutation, "policyCid")?.into());
            target.insert(
                "policyBytes".into(),
                map_text(mutation, "policyBytes")?.into(),
            );
        }
        "envelope.target.origin" => {
            let target = scenario
                .get_mut("envelope")
                .and_then(Value::as_object_mut)
                .and_then(|envelope| envelope.get_mut("target"))
                .and_then(Value::as_object_mut)
                .ok_or("envelope target")?;
            target.insert("origin".into(), value.ok_or("envelope origin")?);
        }
        "createInvitationRequest.shareUrl" => {
            preimage_body_mut(scenario, "createInvitationRequest")?
                .insert("shareUrl".into(), value.ok_or("share URL")?);
        }
        "inviteAuthorization.documentName" => {
            let candidates = map_object(mutation, "candidateArtifactByKind")?;
            let candidate = candidates
                .get(kind)
                .cloned()
                .ok_or("document-name candidate artifact")?;
            let message = candidate
                .get("message")
                .cloned()
                .ok_or("document-name candidate message")?;
            let artifacts = scenario
                .get_mut("artifacts")
                .and_then(Value::as_array_mut)
                .ok_or("artifacts")?;
            let index = artifacts
                .iter()
                .position(|artifact| {
                    artifact.get("name").and_then(Value::as_str) == Some("inviteAuthorization")
                })
                .ok_or("inviteAuthorization artifact")?;
            artifacts[index] = candidate;
            scenario["authorization"] = message;
        }
        "inviteAuthorization.recipientEmail" => {
            artifact_message_mut(scenario, "inviteAuthorization")?
                .insert("recipientEmail".into(), value.ok_or("recipient email")?);
        }
        "holderBinding.redemptionId" | "holderBinding.invitationId" => {
            let field = target.rsplit('.').next().ok_or("binding field")?;
            artifact_message_mut(scenario, "holderBinding")?
                .insert(field.into(), value.ok_or("binding value")?);
        }
        "policyPresentation.contentSource.path" => {
            let mut source = object(scenario, "source")?.clone();
            source.insert("path".into(), value.ok_or("content source path")?);
            artifact_message_mut(scenario, "policyPresentation")?
                .insert("contentSource".into(), Value::Object(source));
        }
        "policyPresentation.shareId"
        | "policyPresentation.shareCid"
        | "policyPresentation.policyCid"
        | "policyPresentation.targetOrigin"
        | "policyPresentation.nodeAudience"
        | "policyPresentation.holderDid"
        | "policyPresentation.contentSourceDigest"
        | "policyPresentation.action"
        | "policyPresentation.resource" => {
            let field = target.rsplit('.').next().ok_or("presentation field")?;
            artifact_message_mut(scenario, "policyPresentation")?
                .insert(field.into(), value.ok_or("presentation value")?);
        }
        "envelope.domain" => {
            artifact_mut(scenario, "envelope")?
                .insert("domain".into(), value.ok_or("envelope domain")?);
        }
        "value" => {
            scenario["nativeMutation"] = Value::Object(
                [(
                    "jsonLiteral".into(),
                    Value::String(map_text(mutation, "jsonLiteral")?.into()),
                )]
                .into_iter()
                .collect(),
            );
        }
        "invitationId" => {
            preimage_body_mut(scenario, "claimRedeemRequest")?
                .insert("invitationId".into(), value.ok_or("invitation ID")?);
        }
        "signature" => {
            artifact_mut(scenario, "readInvocation")?
                .get_mut("signature")
                .and_then(Value::as_object_mut)
                .ok_or("read signature")?
                .insert("value".into(), value.ok_or("signature value")?);
        }
        "holderBinding.signature.kid" => {
            preimage_body_mut(scenario, "claimRedeemRequest")?
                .get_mut("holderProof")
                .and_then(Value::as_object_mut)
                .ok_or("holder proof")?
                .insert("kid".into(), value.ok_or("holder kid")?);
        }
        "holderBinding.signature.value" => {
            artifact_mut(scenario, "holderBinding")?
                .get_mut("signature")
                .and_then(Value::as_object_mut)
                .ok_or("holder signature")?
                .insert("value".into(), value.ok_or("holder signature value")?);
        }
        "holderBinding.holderDid" => {
            if let Some(candidate) = mutation.get("candidateArtifact") {
                let artifacts = scenario
                    .get_mut("artifacts")
                    .and_then(Value::as_array_mut)
                    .ok_or("artifacts")?;
                let index = artifacts
                    .iter()
                    .position(|artifact| text(artifact, "name").ok() == Some("holderBinding"))
                    .ok_or("holder artifact")?;
                artifacts[index] = candidate.clone();
            } else {
                artifact_message_mut(scenario, "holderBinding")?
                    .insert("holderDid".into(), value.ok_or("holder DID")?);
            }
        }
        "readInvocation.signature.value" => {
            let signature = artifact_mut(scenario, "readInvocation")?
                .get_mut("signature")
                .and_then(Value::as_object_mut)
                .ok_or("read signature")?;
            let bytes = mutation
                .get("bytes")
                .and_then(Value::as_u64)
                .map(|value| value as usize)
                .ok_or("signature byte count")?;
            let original = b64_map(signature, "value")?;
            assert_ok(bytes < original.len(), "signature truncation length")?;
            signature.insert(
                "value".into(),
                Value::String(URL_SAFE_NO_PAD.encode(&original[..bytes])),
            );
        }
        "sql.argumentsDigest" | "sql.arguments" => {
            let source = scenario
                .get_mut("source")
                .and_then(Value::as_object_mut)
                .ok_or("source")?;
            if mutation.get("operation").and_then(Value::as_str) == Some("replace-object") {
                source.insert(
                    "arguments".into(),
                    mutation
                        .get("value")
                        .cloned()
                        .ok_or("SQL arguments object")?,
                );
            } else {
                let arguments = source
                    .get_mut("arguments")
                    .and_then(Value::as_object_mut)
                    .ok_or("SQL arguments")?;
                let argument_value =
                    if let Some(literal) = mutation.get("jsonLiteral").and_then(Value::as_str) {
                        serde_json::from_str(literal).map_err(|e| e.to_string())?
                    } else {
                        value.ok_or("SQL argument")?
                    };
                let field = map_text(mutation, "field")?;
                arguments.insert(
                    if target == "sql.argumentsDigest" {
                        field.rsplit('.').next().unwrap_or("field")
                    } else {
                        field
                    }
                    .into(),
                    argument_value,
                );
            }
        }
        "sqlSource.query" => {
            scenario
                .get_mut("source")
                .and_then(Value::as_object_mut)
                .ok_or("source")?
                .insert(map_text(mutation, "field")?.into(), value.ok_or("query")?);
        }
        "policy.action" => {
            scenario
                .get_mut("policy")
                .and_then(Value::as_object_mut)
                .ok_or("policy")?
                .insert("action".into(), value.ok_or("policy action")?);
        }
        "credential.claims.sub" | "credential.claims.status" => {
            let claims = scenario
                .get_mut("credential")
                .and_then(Value::as_object_mut)
                .and_then(|credential| credential.get_mut("claims"))
                .and_then(Value::as_object_mut)
                .ok_or("credential claims")?;
            let field = target.rsplit('.').next().ok_or("credential field")?;
            if mutation.get("operation").and_then(Value::as_str) == Some("delete") {
                claims.remove(field);
            } else {
                claims.insert(field.into(), value.ok_or("credential value")?);
            }
        }
        target
            if target.starts_with("credential.") && mutation.get("credentialByKind").is_some() =>
        {
            scenario["credential"] = mutation
                .get("credentialByKind")
                .and_then(Value::as_object)
                .and_then(|values| values.get(kind))
                .cloned()
                .ok_or("credential candidate")?;
        }
        "credential.disclosures[0].path" => {
            let disclosure = scenario
                .get_mut("credential")
                .and_then(Value::as_object_mut)
                .and_then(|credential| credential.get_mut("disclosures"))
                .and_then(Value::as_array_mut)
                .and_then(|disclosures| disclosures.first_mut())
                .and_then(Value::as_object_mut)
                .ok_or("credential disclosure")?;
            disclosure.insert("path".into(), value.ok_or("disclosure path")?);
        }
        "nonce.state" | "invitation.version" | "otp.attempts" => match target {
            "nonce.state" => {
                states["nativeNonceAttempt"] = serde_json::json!({
                    "current": mutation.get("from").cloned().ok_or("nonce from")?,
                    "operation": "consume",
                    "requested": mutation.get("to").cloned().ok_or("nonce to")?
                });
            }
            "invitation.version" => {
                states["nativeInvitationAttempt"] = serde_json::json!({
                    "activeVersion": 2,
                    "attemptedVersion": mutation.get("value").cloned().ok_or("invitation version")?,
                    "state": "ACTIVE"
                });
            }
            "otp.attempts" => {
                states["nativeOtpAttempt"] = serde_json::json!({
                    "attempts": mutation.get("value").cloned().ok_or("OTP attempts")?,
                    "submittedCorrectCode": true
                });
            }
            _ => return Err("unknown state mutation".into()),
        },
        "read.proof" => {
            let name = if kind == "sql" {
                "sqlReadRequest"
            } else {
                "kvReadRequest"
            };
            preimage_body_mut(scenario, name)?.remove("proof");
        }
        "fragment" | "scanner.fragment" | "resendRequest.email" => {
            if target == "fragment" {
                scenario["fragment"] = value.ok_or("fragment")?;
                states["nativeScannerGetAttempt"] = serde_json::json!({
                    "method": "GET",
                    "before": "ACTIVE(v1)",
                    "after": "CONSUMED(v1)"
                });
            } else if target == "scanner.fragment" {
                scenario["fragment"] = value.ok_or("scanner fragment")?;
            } else {
                preimage_body_mut(scenario, "resendRequest")?
                    .insert("email".into(), value.ok_or("resend email")?);
            }
        }
        "witness.routes" => {
            let action = map_text(object(scenario, "source")?, "action")?;
            let route = format!(
                "/v1/{}",
                action.strip_prefix("tinycloud.").unwrap_or(action)
            );
            scenario["nativeCapability"] = Value::Object(
                [(
                    "routes".into(),
                    Value::Array(vec![Value::String(route), value.ok_or("capability route")?]),
                )]
                .into_iter()
                .collect(),
            );
        }
        "node.origin" => {
            scenario["nativeCapability"] = Value::Object(
                [(
                    "origin".into(),
                    Value::String(
                        value
                            .ok_or("capability origin")?
                            .as_str()
                            .ok_or("origin")?
                            .into(),
                    ),
                )]
                .into_iter()
                .collect(),
            );
        }
        "sqlReadRequest.resource" => {
            preimage_body_mut(scenario, "sqlReadRequest")?
                .insert("resource".into(), value.ok_or("read resource")?);
        }
        "claimRedeemRequest.mailboxProof" => {
            let name = if map_text(mutation, "method")? == "otp" {
                "claimRedeemOtpRequest"
            } else {
                "claimRedeemRequest"
            };
            preimage_body_mut(scenario, name)?
                .insert("mailboxProof".into(), value.ok_or("mailbox proof")?);
        }
        "policyChallengeResponse.proof" | "policySessionResponse.proof" => {
            let response_name = if target.starts_with("policyChallenge") {
                "policyChallengeResponse"
            } else {
                "policySessionResponse"
            };
            let artifact_name = map_text(mutation, "artifact")?;
            let signature = object(
                array(scenario, "artifacts")?
                    .iter()
                    .find(|artifact| text(artifact, "name").ok() == Some(artifact_name))
                    .ok_or("proof artifact")?,
                "signature",
            )?;
            let proof = Value::Object(
                [
                    ("alg".into(), Value::String("EdDSA".into())),
                    ("kid".into(), map_text(mutation, "signer")?.into()),
                    ("signature".into(), map_text(signature, "value")?.into()),
                ]
                .into_iter()
                .collect(),
            );
            preimage_body_mut(scenario, response_name)?.insert("proof".into(), proof);
        }
        "credential.claims._sd_alg" => {
            scenario
                .get_mut("credential")
                .and_then(Value::as_object_mut)
                .and_then(|credential| credential.get_mut("claims"))
                .and_then(Value::as_object_mut)
                .ok_or("credential claims")?
                .remove("_sd_alg");
        }
        "credential.disclosures[0].encoded" => {
            let shape = mutation
                .get("arrayShape")
                .and_then(Value::as_array)
                .ok_or("disclosure shape")?;
            let encoded =
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(shape).map_err(|e| e.to_string())?);
            let credential = scenario
                .get_mut("credential")
                .and_then(Value::as_object_mut)
                .ok_or("credential")?;
            let issuer = map_text(credential, "credential")?
                .split('~')
                .next()
                .ok_or("issuer JWT")?
                .to_owned();
            credential.insert(
                "credential".into(),
                Value::String(format!("{issuer}~{encoded}~")),
            );
            credential
                .get_mut("disclosures")
                .and_then(Value::as_array_mut)
                .and_then(|disclosures| disclosures.first_mut())
                .and_then(Value::as_object_mut)
                .ok_or("credential disclosure")?
                .insert("encoded".into(), encoded.into());
        }
        target if target.starts_with("enrollment.") => {
            scenario["enrollment"] = mutation
                .get("enrollment")
                .cloned()
                .ok_or("enrollment candidate")?;
        }
        target if target.starts_with("authorityMaterial.") => {
            if target.ends_with("signature.value") {
                let artifacts = scenario
                    .get_mut("artifacts")
                    .and_then(Value::as_array_mut)
                    .ok_or("artifacts")?;
                let artifact = artifacts
                    .iter_mut()
                    .find(|artifact| text(artifact, "name").ok() == Some("authorityMaterial"))
                    .ok_or("authority artifact")?;
                let signature = artifact
                    .get_mut("signature")
                    .and_then(Value::as_object_mut)
                    .ok_or("authority signature")?;
                let encoded = map_text(signature, "value")?;
                let mut bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|e| e.to_string())?;
                let first = bytes.first_mut().ok_or("authority signature bytes")?;
                *first ^= 1;
                signature.insert("value".into(), URL_SAFE_NO_PAD.encode(bytes).into());
            } else {
                let field = map_text(mutation, "field")?;
                let mut parts = field.split('.');
                let first = parts.next().ok_or("authority field")?;
                let second = parts.next();
                let material = scenario
                    .get_mut("authorityMaterial")
                    .and_then(Value::as_object_mut)
                    .ok_or("authority material")?;
                if let Some(second) = second {
                    material
                        .get_mut(first)
                        .and_then(Value::as_object_mut)
                        .ok_or("authority nested field")?
                        .insert(second.into(), value.ok_or("authority mutation value")?);
                } else {
                    material.insert(first.into(), value.ok_or("authority mutation value")?);
                }
            }
        }
        _ => return Err(format!("unknown native negative target {target}")),
    }
    Ok(())
}
fn validate_mutated_candidate_inner(
    scenario: &Value,
    states: &Value,
    row: &Value,
    kind: &str,
    domains: &Map<String, Value>,
    issuer_key: &VerifyingKey,
) -> Result<()> {
    let target = text(row, "target")?;
    let mutation = object(row, "mutationData")?;
    match target {
        "canonicalEmail" => assert_ok(
            strict_email(text(scenario, "canonicalEmail")?),
            "invalid email accepted",
        ),
        "policyBytes" => {
            let bytes = b64(scenario, "policyBytes")?;
            assert_ok(
                cid(&bytes) == text(scenario, "policyCid")?,
                "policy bytes CID mismatch",
            )
        }
        "sealedBlob" => {
            let blob = b64(scenario, "sealedBlob")?;
            assert_ok(
                cid(&blob) == text(scenario, "shareCid")?,
                "sealed blob CID mismatch",
            )
        }
        "envelope.authorizationTarget.kind" | "envelope.authorizationTarget.policyBytes" => {
            let target = object(
                scenario.get("envelope").ok_or("envelope")?,
                "authorizationTarget",
            )?;
            assert_ok(target.contains_key("kind"), "envelope kind missing")?;
            assert_ok(
                target.contains_key("policyBytes"),
                "envelope policy bytes missing",
            )
        }
        "envelope.authorizationTarget" => {
            let target = object(
                scenario.get("envelope").ok_or("envelope")?,
                "authorizationTarget",
            )?;
            let bytes = b64(&Value::Object(target.clone()), "policyBytes")?;
            assert_ok(
                map_text(target, "kind")? == "policy"
                    && map_text(target, "policyCid")? == text(scenario, "policyCid")?
                    && cid(&bytes) == text(scenario, "policyCid")?,
                "envelope policy target mismatch",
            )
        }
        "envelope.target.origin" => assert_ok(
            map_text(
                object(scenario.get("envelope").ok_or("envelope")?, "target")?,
                "origin",
            )? == text(
                scenario.get("enrollment").ok_or("enrollment")?,
                "targetOrigin",
            )?,
            "envelope origin mismatch",
        ),
        "createInvitationRequest.shareUrl" => {
            let body = map_object(
                object(
                    scenario.get("preimages").ok_or("preimages")?,
                    "createInvitationRequest",
                )?,
                "body",
            )?;
            validate_share_url(map_text(body, "shareUrl")?, scenario)
        }
        "inviteAuthorization.documentName" => {
            let artifact = artifact_named(scenario, "inviteAuthorization")?;
            validate_message_schema(
                "inviteAuthorization",
                artifact.get("message").ok_or("authorization message")?,
                kind,
            )
        }
        "inviteAuthorization.recipientEmail" => assert_ok(
            text(
                artifact_message(scenario, "inviteAuthorization")?,
                "recipientEmail",
            )? == text(scenario, "canonicalEmail")?,
            "authorization recipient mismatch",
        ),
        "holderBinding.redemptionId" | "holderBinding.invitationId" => {
            let field = target.rsplit('.').next().ok_or("binding field")?;
            let binding = artifact_message(scenario, "holderBinding")?;
            let body = map_object(
                object(
                    scenario.get("preimages").ok_or("preimages")?,
                    "claimRedeemRequest",
                )?,
                "body",
            )?;
            assert_ok(
                text(binding, field)? == map_text(body, field)?,
                "binding ID mismatch",
            )
        }
        "policyPresentation.contentSource.path"
        | "policyPresentation.shareId"
        | "policyPresentation.shareCid"
        | "policyPresentation.policyCid"
        | "policyPresentation.targetOrigin"
        | "policyPresentation.nodeAudience"
        | "policyPresentation.holderDid"
        | "policyPresentation.contentSourceDigest"
        | "policyPresentation.action"
        | "policyPresentation.resource" => validate_cross_equations(scenario),
        "policy.action" => assert_ok(
            map_text(object(scenario, "policy")?, "action")?
                == map_text(object(scenario, "source")?, "action")?,
            "policy action/source mismatch",
        ),
        "envelope.domain" => {
            let artifact = array(scenario, "artifacts")?
                .iter()
                .find(|artifact| text(artifact, "name").ok() == Some("envelope"))
                .ok_or("envelope artifact")?;
            let enrollment = scenario.get("enrollment").ok_or("enrollment")?;
            verify_artifact(artifact, "envelope", domains, enrollment)
        }
        "value" => {
            let literal = map_text(object(scenario, "nativeMutation")?, "jsonLiteral")?;
            let parsed: Value = serde_json::from_str(literal).map_err(|e| e.to_string())?;
            jcs(&parsed).map(|_| ())
        }
        "invitationId" => b64_map(
            map_object(
                object(
                    scenario.get("preimages").ok_or("preimages")?,
                    "claimRedeemRequest",
                )?,
                "body",
            )?,
            "invitationId",
        )
        .map(|_| ())
        .map_err(|e| e.to_string()),
        "signature" | "readInvocation.signature.value" => {
            let artifact = array(scenario, "artifacts")?
                .iter()
                .find(|artifact| text(artifact, "name").ok() == Some("readInvocation"))
                .ok_or("read artifact")?;
            let enrollment = scenario.get("enrollment").ok_or("enrollment")?;
            verify_signature_core(artifact, "readInvocation", enrollment)?;
            verify_artifact(artifact, "readInvocation", domains, enrollment)
        }
        "holderBinding.signature.kid" => {
            let binding = artifact_message(scenario, "holderBinding")?;
            let holder = text(binding, "holderDid")?;
            let expected = format!(
                "{}#{}",
                holder,
                holder.strip_prefix("did:key:z").unwrap_or(holder)
            );
            let body = map_object(
                object(
                    scenario.get("preimages").ok_or("preimages")?,
                    "claimRedeemRequest",
                )?,
                "body",
            )?;
            let proof = map_object(body, "holderProof")?;
            assert_ok(map_text(proof, "kid")? == expected, "holder kid mismatch")
        }
        "holderBinding.signature.value" | "holderBinding.holderDid" => {
            let holder = text(artifact_message(scenario, "holderBinding")?, "holderDid")?;
            let raw = did_key_bytes(holder)?;
            let key = VerifyingKey::from_bytes(&raw).map_err(|e| e.to_string())?;
            assert_ok(!key.is_weak(), "weak holder key")?;
            let artifact = array(scenario, "artifacts")?
                .iter()
                .find(|artifact| text(artifact, "name").ok() == Some("holderBinding"))
                .ok_or("holder artifact")?;
            let enrollment = scenario.get("enrollment").ok_or("enrollment")?;
            verify_signature_core(artifact, "holderBinding", enrollment)?;
            verify_artifact(artifact, "holderBinding", domains, enrollment)?;
            if target == "holderBinding.holderDid" {
                validate_cross_artifact_holder(scenario)?;
            }
            validate_cross_equations(scenario)
        }
        "sql.argumentsDigest" | "sql.arguments" => {
            let source = scenario.get("source").ok_or("source")?;
            validate_sql_arguments(source)
        }
        "sqlSource.query" => assert_ok(
            !object(scenario, "source")?.contains_key("query"),
            "arbitrary SQL query field accepted",
        ),
        "credential.claims.sub" => {
            let credential = object(scenario, "credential")?;
            assert_ok(
                map_text(map_object(credential, "claims")?, "sub")?
                    == map_text(credential, "holderDid")?,
                "credential subject mismatch",
            )
        }
        "credential.disclosures[0].path" => {
            let disclosure = map_array(object(scenario, "credential")?, "disclosures")?
                .first()
                .ok_or("disclosure")?;
            assert_ok(
                text(disclosure, "path")? == "/email",
                "legacy disclosure path",
            )
        }
        "credential.claims.status" => assert_ok(
            !map_object(object(scenario, "credential")?, "claims")?.contains_key("status"),
            "unsupported credential status",
        ),
        "nonce.state" => {
            let changed = object(states, "nativeNonceAttempt")?;
            let current = map_text(changed, "current")?;
            let requested = map_text(changed, "requested")?;
            assert_ok(
                map_text(changed, "operation")? == "consume"
                    && current == "VERIFYING"
                    && requested == "CONSUMED",
                "invalid nonce transition accepted",
            )
        }
        "read.proof" => {
            let name = if kind == "sql" {
                "sqlReadRequest"
            } else {
                "kvReadRequest"
            };
            let body = map_object(
                object(scenario.get("preimages").ok_or("preimages")?, name)?,
                "body",
            )?;
            map_object(body, "proof").map(|_| ())
        }
        "invitation.version" => {
            let attempt = object(states, "nativeInvitationAttempt")?;
            assert_ok(
                map_text(attempt, "state")? == "ACTIVE"
                    && attempt.get("attemptedVersion") == attempt.get("activeVersion"),
                "old invitation version accepted after resend",
            )
        }
        "otp.attempts" => {
            let attempt = object(states, "nativeOtpAttempt")?;
            let attempts = attempt
                .get("attempts")
                .and_then(Value::as_i64)
                .ok_or("OTP attempts")?;
            let threshold = map_object(object(states, "semantics")?, "otp")?
                .get("wrongAttemptsBeforeLock")
                .and_then(Value::as_i64)
                .ok_or("OTP threshold")?;
            assert_ok(
                !(attempts >= threshold
                    && attempt.get("submittedCorrectCode") == Some(&Value::Bool(true))),
                "locked OTP accepted",
            )
        }
        "fragment" | "scanner.fragment" => {
            let url = text(scenario, "fragment")?;
            validate_scanner_fragment(url, scenario)?;
            if target == "fragment" {
                let attempt = object(states, "nativeScannerGetAttempt")?;
                assert_ok(
                    map_text(attempt, "method")? == "GET"
                        && map_text(attempt, "after")? == map_text(attempt, "before")?,
                    "GET consumed claim",
                )
            } else {
                Ok(())
            }
        }
        "resendRequest.email" => assert_ok(
            !map_object(
                object(
                    scenario.get("preimages").ok_or("preimages")?,
                    "resendRequest",
                )?,
                "body",
            )?
            .contains_key("email"),
            "recipient email accepted by resend",
        ),
        "witness.routes" => {
            let capability = object(scenario, "nativeCapability")?;
            let routes = map_array(capability, "routes")?;
            let action = text(scenario.get("source").ok_or("source")?, "action")?;
            let expected = format!(
                "/v1/{}",
                action.strip_prefix("tinycloud.").unwrap_or(action)
            );
            assert_ok(
                routes.len() == 1
                    && routes
                        .iter()
                        .all(|route| route.as_str() == Some(expected.as_str())),
                "capability route outside allowlist",
            )
        }
        "node.origin" => {
            let capability = object(scenario, "nativeCapability")?;
            let origin = map_text(capability, "origin")?;
            assert_ok(
                !origin.contains('*')
                    && origin
                        == text(
                            scenario.get("enrollment").ok_or("enrollment")?,
                            "targetOrigin",
                        )?,
                "capability wildcard origin",
            )
        }
        "sqlReadRequest.resource" => {
            let preimage = map_object(
                object(
                    scenario.get("preimages").ok_or("preimages")?,
                    "sqlReadRequest",
                )?,
                "body",
            )?;
            let canonical = jcs(&Value::Object(preimage.clone()))?;
            assert_ok(
                digest(canonical.as_bytes())
                    == map_text(
                        object(
                            scenario.get("preimages").ok_or("preimages")?,
                            "sqlReadRequest",
                        )?,
                        "digest",
                    )?,
                "read body digest mismatch",
            )
        }
        "claimRedeemRequest.mailboxProof" => {
            let method = map_text(mutation, "method")?;
            let name = if method == "otp" {
                "claimRedeemOtpRequest"
            } else {
                "claimRedeemRequest"
            };
            let body = map_object(
                object(scenario.get("preimages").ok_or("preimages")?, name)?,
                "body",
            )?;
            let expected_name = if method == "otp" {
                "claimChallengeOtpRequest"
            } else {
                "claimChallengeMagicRequest"
            };
            let expected_body = map_object(
                object(scenario.get("preimages").ok_or("preimages")?, expected_name)?,
                "body",
            )?;
            assert_ok(
                map_text(body, "method")? == method
                    && map_text(body, "mailboxProof")?
                        == if method == "otp" {
                            map_text(expected_body, "otp")?
                        } else {
                            map_text(expected_body, "claimSecret")?
                        },
                "redeem method/proof mismatch",
            )
        }
        "policyChallengeResponse.proof" | "policySessionResponse.proof" => {
            let response_name = if target.starts_with("policyChallenge") {
                "policyChallengeResponse"
            } else {
                "policySessionResponse"
            };
            let artifact_name = map_text(mutation, "artifact")?;
            let artifact = array(scenario, "artifacts")?
                .iter()
                .find(|artifact| text(artifact, "name").ok() == Some(artifact_name))
                .ok_or("proof artifact")?;
            let response = map_object(
                object(scenario.get("preimages").ok_or("preimages")?, response_name)?,
                "body",
            )?;
            proof_matches(
                &Value::Object(response.clone()),
                artifact,
                scenario.get("enrollment").ok_or("enrollment")?,
                "response proof",
            )
        }
        "credential.claims._sd_alg" | "credential.disclosures[0].encoded" => {
            validate_sd_jwt(scenario, issuer_key)
        }
        target if target.starts_with("credential.") => validate_sd_jwt(scenario, issuer_key),
        target if target.starts_with("enrollment.") => {
            let enrollment = object(scenario, "enrollment")?;
            assert_ok(
                map_text(enrollment, "targetOrigin")? == "https://node.example",
                "enrollment authority origin",
            )?;
            assert_ok(
                map_text(enrollment, "nodeAudience")? == "did:web:node.example",
                "enrollment authority audience",
            )?;
            assert_ok(
                map_text(enrollment, "invitationKid")? == "did:web:node.example#invitation-key-1",
                "enrollment key rotation",
            )?;
            assert_ok(
                enrollment.get("keyVersion") == Some(&Value::from(1)),
                "enrollment key version",
            )?;
            assert_ok(
                enrollment.get("enabled") == Some(&Value::Bool(true)),
                "enrollment enabled",
            )
        }
        target if target.starts_with("authorityMaterial.") => {
            if target.ends_with("signature.value") {
                let artifact = artifact_named(scenario, "authorityMaterial")?;
                verify_artifact(
                    artifact,
                    "authorityMaterial",
                    domains,
                    scenario.get("enrollment").ok_or("enrollment")?,
                )
            } else {
                let material = scenario
                    .get("authorityMaterial")
                    .ok_or("authority material")?;
                validate_message_schema("authorityMaterial", material, kind)?;
                let material_object = material.as_object().ok_or("authority material object")?;
                assert_ok(
                    map_text(material_object, "sharePolicyCid")? == text(scenario, "policyCid")?
                        && map_text(material_object, "shareDelegationCid")?
                            == text(scenario, "delegationCid")?,
                    "authority Share identifier mapping",
                )?;
                let attestation = object(
                    map_value(material_object, "attestation", "authority material")?,
                    "attestation",
                )?;
                let basis = serde_json::json!({"origin": map_value(attestation, "origin", "attestation")?, "audience": map_value(attestation, "audience", "attestation")?, "enforcerKid": map_value(attestation, "enforcerKid", "attestation")?, "keyVersion": map_value(attestation, "keyVersion", "attestation")?, "measurement": map_value(attestation, "measurement", "attestation")?});
                assert_ok(
                    digest(jcs(&basis)?.as_bytes()) == map_text(attestation, "digest")?,
                    "attestation measurement digest",
                )?;
                let status = object(
                    map_value(material_object, "status", "authority material")?,
                    "status",
                )?;
                assert_ok(
                    map_text(status, "state")? == "active"
                        && map_value(status, "sequence", "status")?.as_i64() == Some(7)
                        && map_text(status, "freshUntil")? >= text(scenario, "evaluationTime")?
                        && map_text(status, "freshUntil")? <= map_text(attestation, "expiresAt")?,
                    "authority status freshness",
                )?;
                Ok(())
            }
        }
        _ => Err(format!("unknown native negative target {target}")),
    }
}

fn validate_negative_candidate(
    scenario: &Value,
    states: &Value,
    row: &Value,
    kind: &str,
    domains: &Map<String, Value>,
    test_keys: &Value,
    issuer_key: &VerifyingKey,
) -> std::result::Result<(), NegativeRejection> {
    let target = text(row, "target")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    let mutation = object(row, "mutationData")
        .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
    match target {
        "createInvitationRequest.shareUrl" => {
            let preimages = scenario
                .get("preimages")
                .ok_or_else(|| rejection(RejectionStage::ContractValidation, "preimages"))?;
            let request = object(preimages, "createInvitationRequest")
                .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
            let body = map_object(request, "body")
                .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
            let url = map_text(body, "shareUrl")
                .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
            validate_share_url_boundary(url, scenario)
        }
        "scanner.fragment" => {
            let url = text(scenario, "fragment")
                .map_err(|detail| rejection(RejectionStage::ContractValidation, detail))?;
            validate_scanner_fragment_boundary(url, scenario)
        }
        "inviteAuthorization.documentName" => {
            validate_document_name_boundary(scenario, kind, domains)
        }
        "holderBinding.holderDid" if mutation.contains_key("candidateArtifact") => {
            validate_cross_artifact_holder_boundary(scenario, domains)
        }
        "holderBinding.signature.value" => validate_holder_signature_boundary(scenario, domains),
        target
            if target.starts_with("credential.") && mutation.contains_key("credentialByKind") =>
        {
            validate_credential_candidate(scenario, test_keys, mutation, kind, issuer_key)
        }
        target if target.starts_with("enrollment.") => validate_enrollment_boundary(scenario),
        _ => validate_mutated_candidate_inner(scenario, states, row, kind, domains, issuer_key)
            .map_err(|detail| rejection(RejectionStage::ContractValidation, detail)),
    }
}

fn validate_negative_native(
    positive: &Value,
    negative: &Value,
    states: &Value,
    domains: &Map<String, Value>,
    test_keys: &Value,
    issuer_key: &VerifyingKey,
) -> Result<()> {
    let rows = array(negative, "cases")?;
    let scenarios = array(positive, "scenarios")?;
    let mut ids = Vec::new();
    for row in rows {
        let id = text(row, "id")?;
        assert_ok(
            known_native_id(id),
            &format!("unknown native negative ID {id}"),
        )?;
        assert_ok(
            !ids.iter().any(|seen| seen == id),
            "duplicate native negative ID",
        )?;
        ids.push(id.to_string());
        assert_ok(
            text(row, "expected")? == "reject",
            "negative expected marker",
        )?;
        assert_ok(
            [
                "contract-validation",
                "credential-holder",
                "credential-scope",
                "credential-time",
                "credential-vct",
                "cross-artifact-holder",
                "document-name-bytes",
                "issuer-key",
                "issuer-trust",
                "node-authority",
                "node-enrollment",
                "node-key-retirement",
                "node-key-rotation",
                "share-url-fragment",
                "share-url-fragment-encoding",
                "share-url-key",
                "share-url-origin",
                "share-url-port",
                "share-url-path",
                "share-url-query",
                "share-url-scheme",
                "scanner-fragment-encoding",
                "signature-encoding",
            ]
            .contains(&text(row, "rejectionStage")?),
            "unknown negative rejection stage",
        )?;
        let mutation_text = serde_json::to_string(row.get("mutationData").ok_or("mutation data")?)
            .map_err(|e| e.to_string())?;
        assert_ok(
            !mutation_text.contains("scenario."),
            "symbolic negative mutation",
        )?;
        let applies = array(row, "appliesTo")?;
        for scenario in scenarios {
            let kind = text(scenario, "kind")?;
            if !applies.iter().any(|value| value.as_str() == Some(kind)) {
                continue;
            }
            let mut candidate = scenario.clone();
            let mut state_candidate = states.clone();
            apply_negative_mutation(&mut candidate, &mut state_candidate, row, kind)?;
            let expected_stage = RejectionStage::parse(text(row, "rejectionStage")?)
                .ok_or("unknown negative rejection stage")?;
            if let Err(rejection) = validate_negative_candidate(
                &candidate,
                &state_candidate,
                row,
                kind,
                domains,
                test_keys,
                issuer_key,
            ) {
                assert_ok(
                    rejection.stage == expected_stage,
                    &format!(
                        "negative rejection stage {id}/{kind}: expected {}, got {} ({})",
                        expected_stage.as_str(),
                        rejection.stage.as_str(),
                        rejection.detail
                    ),
                )?;
            } else {
                return Err(format!("native negative accepted: {id}/{kind}"));
            }
        }
    }
    assert_ok(ids.len() == rows.len(), "native negative coverage")?;
    execute_operation_program(states)
}
#[allow(dead_code)]
fn validate_recovery_native(states: &Value) -> Result<()> {
    let recovery_value = states.get("issuanceRecovery").ok_or("issuanceRecovery")?;
    let recovery = recovery_value
        .as_object()
        .ok_or("issuanceRecovery object")?;
    assert_ok(
        recovery.get("seedCiphertext") == recovery.get("retrySeedCiphertext")
            && recovery.get("pendingSeedCiphertext") == recovery.get("retryPendingSeedCiphertext")
            && recovery.get("seedCiphertext") == recovery.get("pendingSeedCiphertext"),
        "retry seed bytes changed",
    )?;
    let timeline = map_array(recovery, "timeline")?;
    assert_ok(timeline.len() == 5, "recovery timeline length")?;
    assert_ok(
        text(&timeline[0], "state")? == "PENDING_ENCRYPTED"
            && text(&timeline[1], "event")? == "credential_generated_then_crash"
            && timeline[1].get("credentialGenerated") == Some(&Value::Bool(true))
            && timeline[1].get("durableCompletion") == Some(&Value::Bool(false))
            && text(&timeline[2], "event")? == "retry_same_seed"
            && text(&timeline[3], "event")? == "prepare_atomic_success"
            && timeline[3].get("durableCompletion") == Some(&Value::Bool(false))
            && timeline[3].get("resultPersisted") == Some(&Value::Bool(false))
            && timeline[3].get("consumedPersisted") == Some(&Value::Bool(false))
            && text(&timeline[4], "state")? == "CONSUMED"
            && text(&timeline[4], "event")? == "atomic_credential_result_consumed_persisted"
            && timeline[4].get("credentialPersisted") == Some(&Value::Bool(true))
            && timeline[4].get("durableCompletion") == Some(&Value::Bool(true))
            && timeline[4].get("durableCompletionAt")
                == Some(&Value::from("2026-07-16T12:00:03.000Z"))
            && timeline[4].get("invitationState") == Some(&Value::from("CONSUMED"))
            && timeline[4].get("consumedPersisted") == Some(&Value::Bool(true))
            && timeline[4].get("resultPersisted") == Some(&Value::Bool(true))
            && timeline[4].get("atomicConsumedAndResult") == Some(&Value::Bool(true))
            && timeline[4].get("atomicCredentialResultInvitationConsumedAndSeedDeletion")
                == Some(&Value::Bool(true))
            && timeline[4].get("resultDigest") == recovery.get("resultDigest"),
        "recovery timeline ordering",
    )?;
    for event in &timeline[..4] {
        assert_ok(
            event.get("seedEncrypted") == Some(&Value::Bool(true)),
            "pending seed must remain encrypted",
        )?;
    }
    assert_ok(
        timeline[4].get("seedEncrypted") == Some(&Value::Bool(false)),
        "consumed seed cleanup",
    )?;
    let failure = map_array(recovery, "terminalFailureTimeline")?;
    assert_ok(
        failure.len() == 3
            && text(&failure[0], "state")? == "PENDING_ENCRYPTED"
            && failure[0].get("seedEncrypted") == Some(&Value::Bool(true))
            && text(&failure[1], "state")? == "RETRYING"
            && failure[1].get("seedEncrypted") == Some(&Value::Bool(true))
            && text(&failure[2], "state")? == "TERMINAL_ERROR"
            && text(&failure[2], "event")? == "atomic_terminal_result_consumed_persisted"
            && failure[2].get("terminalResultPersisted") == Some(&Value::Bool(true))
            && failure[2].get("terminalErrorPersisted") == Some(&Value::Bool(true))
            && failure[2].get("resultPersisted") == Some(&Value::Bool(true))
            && failure[2].get("invitationState") == Some(&Value::from("CONSUMED"))
            && failure[2].get("consumedPersisted") == Some(&Value::Bool(true))
            && failure[2].get("atomicConsumedAndResult") == Some(&Value::Bool(true))
            && failure[2].get("seedEncrypted") == Some(&Value::Bool(false))
            && failure[2].get("atomicTerminalAndSeedDeletion") == Some(&Value::Bool(true))
            && failure[2].get("atomicTerminalResultInvitationConsumedAndSeedDeletion")
                == Some(&Value::Bool(true))
            && text(&failure[2], "errorCode")? == "credential_issuance_failed",
        "atomic terminal failure",
    )?;
    let invariants = map_object(recovery, "invariants")?;
    for key in [
        "pendingSeedEncrypted",
        "retrySeedByteIdentical",
        "completionRequiresDurableWrite",
        "consumedAndResultPersistedAtomically",
        "noDurableResultBeforeAtomicSuccess",
        "terminalResultAndConsumedPersistedAtomically",
        "terminalResolutionAtomic",
        "cleanupRefusesPendingSeed",
    ] {
        assert_ok(invariants.get(key) == Some(&Value::Bool(true)), key)?;
    }
    assert_ok(
        invariants.get("durableCompletionAt") == Some(&Value::from("2026-07-16T12:00:03.000Z"))
            && invariants.get("redactionWindowSeconds") == Some(&Value::from(900))
            && map_text(invariants, "redactionStartsOnlyAt")? == "durable_completion"
            && map_text(invariants, "redactionMeasuredFrom")? == "2026-07-16T12:00:03.000Z"
            && map_text(invariants, "redactionAt")? == "2026-07-16T12:15:03.000Z",
        "redaction window",
    )?;
    let cleanup = map_object(recovery, "cleanup")?;
    assert_ok(
        map_text(cleanup, "pendingSeedAction")? == "refuse"
            && cleanup.get("pendingSeedRemains") == Some(&Value::Bool(true))
            && map_text(cleanup, "completedSeedAction")? == "delete",
        "cleanup policy",
    )?;
    let terminal = map_object(recovery, "terminalResolution")?;
    assert_ok(
        terminal.get("atomic") == Some(&Value::Bool(true))
            && terminal.get("atomicConsumedAndResultPersisted") == Some(&Value::Bool(true))
            && terminal.get("atomicCredentialResultInvitationConsumedAndSeedDeletion")
                == Some(&Value::Bool(true))
            && terminal.get("atomicTerminalAndSeedDeletion") == Some(&Value::Bool(true))
            && terminal.get("atomicTerminalResultInvitationConsumedAndSeedDeletion")
                == Some(&Value::Bool(true))
            && map_text(terminal, "successOutcome")? == "CONSUMED"
            && map_text(terminal, "failureOutcome")? == "TERMINAL_ERROR",
        "terminal resolution",
    )?;
    assert_ok(
        digest(
            &URL_SAFE_NO_PAD
                .decode(map_text(recovery, "resultBytes")?)
                .map_err(|e| e.to_string())?,
        ) == map_text(recovery, "resultDigest")?,
        "result digest",
    )?;
    Ok(())
}
fn expect_string_array(value: &Value, expected: &[&str], label: &str) -> Result<()> {
    let values = value.as_array().ok_or_else(|| format!("{label}: array"))?;
    assert_ok(values.len() == expected.len(), label)?;
    for (actual, wanted) in values.iter().zip(expected) {
        assert_ok(actual.as_str() == Some(*wanted), label)?;
    }
    Ok(())
}

fn operand_text<'a>(operands: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    map_text(operands, key)
}

fn operand_u64(operands: &Map<String, Value>, key: &str) -> Result<u64> {
    operands
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing integer operand {key}"))
}

fn operand_bool(operands: &Map<String, Value>, key: &str) -> Result<bool> {
    operands
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing boolean operand {key}"))
}

fn versioned_state(prefix: &str, version: u64) -> String {
    format!("{prefix}(v{version})")
}

fn parse_versioned_state(state: &str, prefix: &str) -> Result<u64> {
    state
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(')'))
        .ok_or_else(|| format!("invalid {prefix} state"))?
        .parse::<u64>()
        .map_err(|error| error.to_string())
}

fn reduce_operation_commands(
    pre_rows: &Map<String, Value>,
    operation: &str,
    commands: &[Value],
) -> Result<Map<String, Value>> {
    assert_ok(!commands.is_empty(), "operation commands")?;
    let mut durable = pre_rows.clone();
    for command_value in commands {
        let command = exact_object(
            command_value,
            &["name", "operands"],
            &[],
            "operation command",
        )?;
        let name = map_text(command, "name")?;
        let operands = map_object(command, "operands")?;
        let mut scratch = durable.clone();
        std::mem::swap(&mut durable, &mut scratch);
        let invitation = durable
            .get("invitation")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let command_result: std::result::Result<(), CommandExecutionError> = (|| {
            match name {
                "create_invitation" => {
                    assert_ok(operation == "transaction", "create operation")?;
                    let version = operand_u64(operands, "version")?;
                    let claim_material = operand_text(operands, "claimMaterial")?;
                    assert_ok(
                        invitation.as_deref() == Some("ABSENT")
                            && durable.get("outbox") == Some(&Value::Null)
                            && durable.get("claimMaterial")
                                == Some(&Value::String(claim_material.into())),
                        "create precondition",
                    )?;
                    durable.insert(
                        "invitation".into(),
                        Value::String(versioned_state("PENDING_DELIVERY", version)),
                    );
                    durable.insert(
                        "outbox".into(),
                        Value::String(operand_text(operands, "outboxKey")?.into()),
                    );
                }
                "provider_accept" => {
                    assert_ok(operation == "transaction", "provider accept operation")?;
                    let version = operand_u64(operands, "version")?;
                    let expected = versioned_state("PENDING_DELIVERY", version);
                    assert_ok(
                        invitation.as_deref() == Some(expected.as_str())
                            && durable.get("providerAccepted") == Some(&Value::Bool(false)),
                        "provider accept precondition",
                    )?;
                    durable.insert(
                        "invitation".into(),
                        Value::String(versioned_state("ACTIVE", version)),
                    );
                    durable.insert("providerAccepted".into(), Value::Bool(true));
                    durable.insert(
                        "claimMaterial".into(),
                        Value::String(operand_text(operands, "claimMaterialAfter")?.into()),
                    );
                }
                "invalidate_old_version" => {
                    assert_ok(operation == "reject", "invalidation operation")?;
                    let version = operand_u64(operands, "version")?;
                    assert_ok(
                        operand_text(operands, "onlyAfter")? == "provider_acceptance"
                            && durable.get("activeVersion") == Some(&version.into())
                            && durable
                                .get("pendingVersion")
                                .and_then(Value::as_u64)
                                .is_some_and(|pending| pending > version)
                            && durable.get("oldSecret") == Some(&Value::String("present".into())),
                        "premature invalidation precondition",
                    )?;
                    durable.insert("oldSecret".into(), Value::String("retired".into()));
                    return Err(reject_command(name, "premature invalidation"));
                }
                "prepare_resend" => {
                    assert_ok(operation == "transaction", "resend operation")?;
                    let from_version = operand_u64(operands, "fromVersion")?;
                    let to_version = operand_u64(operands, "toVersion")?;
                    let expected = versioned_state("ACTIVE", from_version);
                    assert_ok(
                        invitation.as_deref() == Some(expected.as_str())
                            && durable.get("activeVersion") == Some(&from_version.into())
                            && durable.get("pendingVersion") == Some(&Value::Null),
                        "resend precondition",
                    )?;
                    durable.insert(
                        "invitation".into(),
                        Value::String(versioned_state("PENDING_DELIVERY", to_version)),
                    );
                    durable.insert("pendingVersion".into(), to_version.into());
                    durable.insert(
                        "replacementMaterial".into(),
                        Value::String(operand_text(operands, "replacementMaterial")?.into()),
                    );
                }
                "provider_reject" => {
                    assert_ok(operation == "transaction", "provider reject operation")?;
                    let pending_version = operand_u64(operands, "pendingVersion")?;
                    let restore_version = operand_u64(operands, "restoreVersion")?;
                    let expected = versioned_state("PENDING_DELIVERY", pending_version);
                    assert_ok(
                        invitation.as_deref() == Some(expected.as_str())
                            && durable.get("activeVersion") == Some(&restore_version.into())
                            && durable.get("replacementMaterial")
                                == Some(&Value::String("encrypted".into())),
                        "provider failure precondition",
                    )?;
                    durable.insert(
                        "invitation".into(),
                        Value::String(versioned_state("ACTIVE", restore_version)),
                    );
                    durable.insert("pendingVersion".into(), Value::Null);
                    durable.insert(
                        "replacementMaterial".into(),
                        Value::String(operand_text(operands, "replacementMaterialAfter")?.into()),
                    );
                }
                "provider_accept_then_crash" => {
                    assert_ok(operation == "crash", "provider crash operation")?;
                    let version = operand_u64(operands, "version")?;
                    assert_ok(
                        !operand_text(operands, "idempotencyKey")?.is_empty()
                            && invitation.as_deref()
                                == Some(versioned_state("PENDING_DELIVERY", version).as_str())
                            && durable.get("pendingVersion") == Some(&version.into())
                            && durable.get("providerAccepted") == Some(&Value::Bool(false)),
                        "provider crash precondition",
                    )?;
                    durable.insert("providerAccepted".into(), Value::Bool(true));
                    durable.insert("crashObserved".into(), Value::Bool(true));
                }
                "reconcile_provider_acceptance" => {
                    assert_ok(operation == "retry", "provider retry operation")?;
                    let version = operand_u64(operands, "version")?;
                    let retire_version = operand_u64(operands, "retireVersion")?;
                    assert_ok(
                        !operand_text(operands, "idempotencyKey")?.is_empty()
                            && invitation.as_deref()
                                == Some(versioned_state("PENDING_DELIVERY", version).as_str())
                            && durable.get("providerAccepted") == Some(&Value::Bool(true))
                            && durable.get("crashObserved") == Some(&Value::Bool(true))
                            && durable.get("activeVersion") == Some(&retire_version.into()),
                        "provider retry precondition",
                    )?;
                    durable.insert(
                        "invitation".into(),
                        Value::String(versioned_state("ACTIVE", version)),
                    );
                    durable.insert("activeVersion".into(), version.into());
                    durable.insert("pendingVersion".into(), Value::Null);
                    durable.insert("oldSecret".into(), Value::String("retired".into()));
                    durable.insert(
                        "providerSendCount".into(),
                        operand_u64(operands, "sendCount")?.into(),
                    );
                    durable.remove("providerAccepted");
                    durable.remove("crashObserved");
                }
                "resolve_issuance" => {
                    assert_ok(operation == "transaction", "issuance resolution operation")?;
                    let redemption_id = operand_text(operands, "redemptionId")?;
                    let state = invitation.ok_or("issuance state")?;
                    let state_body = state
                        .strip_prefix("REDEEMING(v")
                        .and_then(|value| value.strip_suffix(')'))
                        .ok_or("issuance state")?;
                    let (version, state_redemption) =
                        state_body.split_once(',').ok_or("issuance state")?;
                    assert_ok(
                        state_redemption == redemption_id
                            && durable.get("seed") == Some(&Value::String("encrypted".into()))
                            && durable.get("result") == Some(&Value::Null)
                            && durable.get("consumed") == Some(&Value::Bool(false)),
                        "issuance precondition",
                    )?;
                    let outcome = operand_text(operands, "outcome")?;
                    let invitation = match outcome {
                        "success" => versioned_state(
                            "CONSUMED",
                            version.parse::<u64>().map_err(|error| error.to_string())?,
                        ),
                        "failure" => "TERMINAL_ERROR".into(),
                        _ => return Err(format!("unknown issuance outcome {outcome}").into()),
                    };
                    durable.insert("invitation".into(), Value::String(invitation));
                    durable.insert(
                        "seed".into(),
                        Value::String(operand_text(operands, "seedAfter")?.into()),
                    );
                    durable.insert(
                        "result".into(),
                        Value::String(operand_text(operands, "result")?.into()),
                    );
                    durable.insert("consumed".into(), Value::Bool(true));
                }
                "atomic_write" => {
                    assert_ok(operation == "reject", "atomic write operation")?;
                    assert_ok(
                        operand_bool(operands, "requireAtomic")?,
                        "atomic write requirement",
                    )?;
                    expect_string_array(
                        operands.get("writes").ok_or("partial-write writes")?,
                        &["result", "consumed"],
                        "partial-write writes",
                    )?;
                    assert_ok(
                        invitation.is_some_and(|state| state.starts_with("REDEEMING(v"))
                            && durable.get("seed") == Some(&Value::String("encrypted".into())),
                        "partial-write precondition",
                    )?;
                    durable.insert("result".into(), Value::String("partial".into()));
                    durable.insert("consumed".into(), Value::Bool(true));
                    return Err(reject_command(name, "partial atomic write"));
                }
                "cleanup_seed" => {
                    assert_ok(operation == "reject", "cleanup operation")?;
                    assert_ok(
                        operand_text(operands, "pendingSeedAction")? == "refuse"
                            && operand_bool(operands, "requiresDurableCompletion")?,
                        "cleanup requirement",
                    )?;
                    assert_ok(
                        invitation.is_some_and(|state| state.starts_with("REDEEMING(v"))
                            && durable.get("seed") == Some(&Value::String("encrypted".into())),
                        "pending cleanup precondition",
                    )?;
                    durable.insert("seed".into(), Value::String("deleted".into()));
                    return Err(reject_command(name, "pending seed cleanup"));
                }
                "redeem_if_active" => {
                    let redemption_id = operand_text(operands, "redemptionId")?;
                    let result = operand_text(operands, "result")?;
                    let state = invitation.ok_or("redemption state")?;
                    if state.starts_with("ACTIVE(v") {
                        assert_ok(operation == "transaction", "redemption operation")?;
                        let version = parse_versioned_state(&state, "ACTIVE(v")?;
                        let attempts = operand_u64(operands, "attempts")?;
                        assert_ok(
                            attempts >= 2
                                && durable.get("redemptionId")
                                    == Some(&Value::String(redemption_id.into()))
                                && durable.get("issuanceCount") == Some(&Value::from(0)),
                            "CAS precondition",
                        )?;
                        let mut issuance_count = durable
                            .get("issuanceCount")
                            .and_then(Value::as_u64)
                            .ok_or("CAS issuance count")?;
                        let mut cached_result = durable
                            .get("result")
                            .and_then(Value::as_str)
                            .map(str::to_owned);
                        let expected_cached_outcome =
                            operands.get("cachedOutcome").ok_or("CAS cached outcome")?;
                        let expected_cached_bytes = jcs(expected_cached_outcome)?;
                        let mut contender_outcomes = Vec::with_capacity(attempts as usize);
                        for attempt in 0..attempts {
                            if issuance_count == 0 {
                                issuance_count += 1;
                                cached_result = Some(result.to_owned());
                                durable.insert(
                                    "invitation".into(),
                                    Value::String(versioned_state("CONSUMED", version)),
                                );
                            } else {
                                assert_ok(
                                    cached_result.as_deref() == Some(result),
                                    &format!("CAS idempotency attempt {attempt}"),
                                )?;
                            }
                            let outcome = Value::Object(
                                [
                                    ("status".into(), Value::String("issued".into())),
                                    (
                                        "result".into(),
                                        Value::String(
                                            cached_result
                                                .as_deref()
                                                .ok_or("CAS contender result")?
                                                .into(),
                                        ),
                                    ),
                                ]
                                .into_iter()
                                .collect(),
                            );
                            assert_ok(
                                jcs(&outcome)? == expected_cached_bytes,
                                &format!("CAS cached outcome bytes {attempt}"),
                            )?;
                            contender_outcomes.push(outcome);
                        }
                        assert_ok(
                            contender_outcomes.len() == attempts as usize,
                            "CAS contender outcome count",
                        )?;
                        assert_ok(issuance_count == 1, "CAS issued more than once")?;
                        assert_ok(cached_result.as_deref() == Some(result), "CAS result cache")?;
                        durable.insert("issuanceCount".into(), issuance_count.into());
                        durable.insert("result".into(), Value::String(result.into()));
                    } else {
                        assert_ok(
                            operation == "reject"
                                && durable.get("redemptionId")
                                    != Some(&Value::String(redemption_id.into()))
                                && durable.get("issuanceCount") == Some(&Value::from(1)),
                            "different redemption precondition",
                        )?;
                        durable.insert("redemptionId".into(), Value::String(redemption_id.into()));
                        durable.insert("result".into(), Value::String(result.into()));
                        let attempted_count = durable
                            .get("issuanceCount")
                            .and_then(Value::as_u64)
                            .ok_or("different redemption issuance count")?
                            + 1;
                        durable.insert("issuanceCount".into(), attempted_count.into());
                        return Err(reject_command(name, "different redemption"));
                    }
                }
                "wrong_otp_attempts" => {
                    assert_ok(operation == "transaction", "OTP operation")?;
                    let state = invitation.ok_or("OTP invitation state")?;
                    let version = parse_versioned_state(&state, "ACTIVE(v")?;
                    let attempts = operand_u64(operands, "attempts")?;
                    let lock_at = operand_u64(operands, "lockAt")?;
                    let invalid_magic = operand_u64(operands, "invalidMagicAttempts")?;
                    let current_invalid = durable
                        .get("invalidMagicOtpAttempts")
                        .and_then(Value::as_u64)
                        .ok_or("invalid magic attempts")?;
                    assert_ok(current_invalid == invalid_magic, "OTP precondition")?;
                    let mut otp_attempts = durable
                        .get("otpAttempts")
                        .and_then(Value::as_u64)
                        .ok_or("OTP attempts")?;
                    for _ in 0..attempts {
                        otp_attempts += 1;
                    }
                    assert_ok(otp_attempts >= lock_at, "OTP lock threshold")?;
                    durable.insert("otpAttempts".into(), otp_attempts.into());
                    durable.insert(
                        "invitation".into(),
                        Value::String(versioned_state("LOCKED", version)),
                    );
                }
                "consume_nonce" => {
                    assert_ok(operation == "reject", "nonce operation")?;
                    let required_state = operand_text(operands, "requiredState")?;
                    assert_ok(
                        durable.get("nonce") != Some(&Value::String(required_state.into())),
                        "nonce replay precondition",
                    )?;
                    durable.insert("nonceReplayAttempted".into(), Value::Bool(true));
                    return Err(reject_command(name, "nonce replay"));
                }
                "reserve_jti" => {
                    assert_ok(operation == "reject", "JTI operation")?;
                    let jti = operand_text(operands, "jti")?;
                    let digest = operand_text(operands, "digest")?;
                    assert_ok(
                        durable.get("jti") == Some(&Value::String(jti.into()))
                            && durable.get("digest") != Some(&Value::String(digest.into())),
                        "JTI replay precondition",
                    )?;
                    durable.insert("digest".into(), Value::String(digest.into()));
                    return Err(reject_command(name, "JTI replay"));
                }
                "scanner_get" => {
                    assert_ok(
                        operation == "read-only"
                            && operand_text(operands, "method")? == "GET"
                            && !operand_bool(operands, "mutate")?,
                        "scanner GET precondition",
                    )?;
                }
                _ => return Err(format!("unknown operation command {name}").into()),
            }
            Ok(())
        })();
        if operation == "reject" {
            let command_rejection = match command_result {
                Ok(()) => return Err(format!("rejected command accepted: {name}")),
                Err(CommandExecutionError::Rejected(rejection)) => rejection,
                Err(CommandExecutionError::Invalid(detail)) => {
                    return Err(format!(
                        "rejected command failed validation: {name}: {detail}"
                    ))
                }
            };
            assert_ok(
                command_rejection.name == name && !command_rejection.detail.is_empty(),
                "typed command rejection name",
            )?;
            assert_ok(
                durable != scratch,
                "rejected command did not attempt a mutation",
            )?;
            let rolled_back = scratch.clone();
            durable = scratch;
            assert_ok(durable == rolled_back, "rejected command rollback")?;
        } else {
            command_result.map_err(|error| match error {
                CommandExecutionError::Rejected(rejection) => format!(
                    "command {name} unexpectedly rejected as {}: {}",
                    rejection.name, rejection.detail
                ),
                CommandExecutionError::Invalid(detail) => format!("command {name}: {detail}"),
            })?;
        }
    }
    Ok(durable)
}

fn execute_operation_program(states: &Value) -> Result<()> {
    let program = array(states, "operationProgram")?;
    assert_ok(program.len() >= 15, "operation program coverage")?;
    let mut ids = HashSet::new();
    for row in program {
        let row = exact_object(
            row,
            &["id", "operation", "pre", "commands", "expected"],
            &[],
            "operation row",
        )?;
        let id = row
            .get("id")
            .and_then(Value::as_str)
            .ok_or("operation ID")?;
        assert_ok(ids.insert(id), "duplicate operation ID")?;
        let operation = row
            .get("operation")
            .and_then(Value::as_str)
            .ok_or("operation kind")?;
        assert_ok(
            matches!(
                operation,
                "transaction" | "reject" | "crash" | "retry" | "read-only"
            ),
            "unknown operation kind",
        )?;
        let pre = exact_object(
            row.get("pre").ok_or("operation pre")?,
            &["durableRows"],
            &[],
            "operation pre",
        )?;
        let expected = exact_object(
            row.get("expected").ok_or("operation expected")?,
            &["durableRows"],
            &[],
            "operation expected",
        )?;
        let pre_rows = map_object(pre, "durableRows")?;
        let expected_rows = map_object(expected, "durableRows")?;
        let commands = row
            .get("commands")
            .and_then(Value::as_array)
            .ok_or("operation commands")?;
        let durable = reduce_operation_commands(pre_rows, operation, commands)?;
        assert_ok(
            durable == *expected_rows,
            &format!(
                "operation reducer output {id}: derived={} expected={}",
                Value::Object(durable.clone()),
                Value::Object(expected_rows.clone())
            ),
        )?;
    }
    Ok(())
}

fn validate_states(states: &Value) -> Result<()> {
    let state_object = exact_object(
        states,
        &[
            "version",
            "testOnly",
            "delivery",
            "invitation",
            "nonce",
            "session",
            "operations",
            "operationProgram",
        ],
        &[],
        "states",
    )?;
    const_string(
        map_value(state_object, "version", "states")?,
        CONTRACT_VERSION,
        "states version",
    )?;
    assert_ok(
        state_object.get("testOnly") == Some(&Value::Bool(true)),
        "states testOnly",
    )?;
    let delivery = array(states, "delivery")?;
    assert_ok(delivery.len() == 4, "delivery state count")?;
    let names = [
        "create-accepted",
        "resend-accepted",
        "resend-provider-failure",
        "crash-after-provider-accept",
    ];
    for name in names {
        assert_ok(
            delivery
                .iter()
                .any(|flow| text(flow, "name").ok() == Some(name)),
            "delivery state name",
        )?;
    }
    for flow in delivery {
        let name = text(flow, "name")?;
        let expected_keys = if name == "crash-after-provider-accept" {
            &["name", "events"][..]
        } else {
            &["name", "events", "providerIdempotencyKey"][..]
        };
        exact_object(flow, expected_keys, &[], "delivery state")?;
        let events = array(flow, "events")?;
        assert_ok(!events.is_empty(), "delivery events")?;
        let mut current = events[0]
            .as_array()
            .and_then(|event| event.first())
            .and_then(Value::as_str)
            .ok_or("delivery event source")?;
        for event in events {
            let pair = event.as_array().ok_or("delivery event pair")?;
            assert_ok(
                pair.len() == 2 && pair[0].as_str() == Some(current),
                "delivery transition source",
            )?;
            current = pair[1].as_str().ok_or("delivery transition target")?;
        }
        if name != "crash-after-provider-accept" {
            assert_ok(
                flow.get("providerIdempotencyKey")
                    .and_then(Value::as_str)
                    .is_some(),
                "delivery idempotency key",
            )?;
        }
    }
    expect_string_array(
        states.get("invitation").ok_or("invitation states")?,
        &[
            "ABSENT",
            "ACTIVE(v1)",
            "REDEEMING(v1,redemption-001)",
            "CONSUMED(v1)",
        ],
        "invitation states",
    )?;
    expect_string_array(
        states.get("nonce").ok_or("nonce states")?,
        &["ISSUED", "VERIFYING", "CONSUMED"],
        "nonce states",
    )?;
    let session = array(states, "session")?;
    assert_ok(
        session
            .iter()
            .any(|value| value.as_str() == Some("EXPIRED"))
            && session
                .iter()
                .any(|value| value.as_str() == Some("REVOKED")),
        "session terminal states",
    )?;
    expect_string_array(
        states.get("operations").ok_or("operations")?,
        &[
            "create_persist_outbox",
            "provider_accept",
            "activate_v1",
            "wrong_otp_x5",
            "lock_v1",
            "resend_persist_v2",
            "provider_accept_v2",
            "invalidate_v1",
            "claim_v2",
            "consume_nonce",
            "crash_after_provider_accept",
            "retry_same_provider_idempotency",
            "same_redemption_idempotent",
            "different_redemption_rejected",
            "scanner_get_no_state_change",
        ],
        "operations",
    )?;
    execute_operation_program(states)?;
    Ok(())
}
fn verify(root: &Path) -> Result<()> {
    let vector_dir = root.join("test/vectors/email-claim-v1");
    let spec_dir = root.join("specs/email-claim-v1");
    let manifest = read_json(&vector_dir.join("manifest.json"))?;
    let manifest_core = {
        let mut value = manifest.clone();
        value
            .as_object_mut()
            .ok_or("manifest object")?
            .remove("manifestDigest");
        value
    };
    assert_ok(
        digest(jcs(&manifest_core)?.as_bytes()) == text(&manifest, "manifestDigest")?,
        "manifest digest mismatch",
    )?;
    let files = object(&manifest, "files")?;
    for (name, expected) in files {
        let path = if name == "README.md"
            || name == "domains.json"
            || name == "schemas.json"
            || name == "authority-material.schema.json"
        {
            spec_dir.join(name)
        } else {
            vector_dir.join(name)
        };
        assert_ok(
            digest(&fs::read(path).map_err(|e| e.to_string())?)
                == expected.as_str().ok_or("file digest")?,
            &format!("file digest mismatch: {name}"),
        )?;
    }
    let domains = read_json(&spec_dir.join("domains.json"))?;
    let schemas = read_json(&spec_dir.join("schemas.json"))?;
    assert_ok(
        domains
            .get("domains")
            .and_then(Value::as_object)
            .and_then(|d| d.get("envelope"))
            .and_then(Value::as_str)
            .map(|d| d.ends_with('\0'))
            .unwrap_or(false),
        "envelope domain missing",
    )?;
    assert_ok(schemas.get("schemas").is_some(), "schemas missing")?;
    validate_capability_registry(&domains)?;
    let positive = read_json(&vector_dir.join("positive.json"))?;
    let negative = read_json(&vector_dir.join("negative.json"))?;
    let states = read_json(&vector_dir.join("states.json"))?;
    let domains_map = object(&domains, "domains")?;
    let issuer_key = seed_verifying_key(&domains, "issuerSeedHex")?;
    validate_issuer_trust(&domains, &issuer_key)?;
    validate_negative(&negative)?;
    validate_states(&states)?;
    validate_negative_native(
        &positive,
        &negative,
        &states,
        domains_map,
        &domains,
        &issuer_key,
    )?;
    for scenario in array(&positive, "scenarios")? {
        exact_object(
            scenario,
            &[
                "kind",
                "testOnly",
                "canonicalEmail",
                "emailHash",
                "source",
                "sourceDigest",
                "policy",
                "policyBytes",
                "policyCid",
                "delegationCid",
                "authorityMaterialHandle",
                "authorityMaterialDigest",
                "authorityMaterial",
                "sealedBlob",
                "shareCid",
                "shareId",
                "envelopeKey",
                "envelope",
                "authorization",
                "reportAbuseToken",
                "evaluationTime",
                "clockSkewSeconds",
                "sdJwtSalt",
                "credential",
                "enrollment",
                "artifacts",
                "signedBytePreimages",
                "preimages",
            ],
            &[],
            "positive scenario",
        )?;
        assert_ok(
            scenario.get("testOnly") == Some(&Value::Bool(true)),
            "positive fixture testOnly",
        )?;
        let kind = text(scenario, "kind")?;
        assert_ok(matches!(kind, "kv" | "sql"), "scenario kind")?;
        valid_time(
            scenario.get("evaluationTime").ok_or("evaluation time")?,
            "evaluation time",
        )?;
        assert_ok(
            scenario
                .get("clockSkewSeconds")
                .and_then(Value::as_i64)
                .is_some_and(|skew| (0..=300).contains(&skew)),
            "clock skew",
        )?;
        assert_ok(
            strict_email(text(scenario, "canonicalEmail")?),
            "canonical email",
        )?;
        valid_digest(scenario.get("emailHash").ok_or("email hash")?, "email hash")?;
        assert_ok(
            digest(text(scenario, "canonicalEmail")?.as_bytes()) == text(scenario, "emailHash")?,
            "email hash preimage",
        )?;
        validate_source(scenario.get("source").ok_or("source")?, kind)?;
        valid_digest(
            scenario.get("sourceDigest").ok_or("source digest")?,
            "source digest",
        )?;
        assert_ok(
            digest(jcs(scenario.get("source").ok_or("source")?)?.as_bytes())
                == text(scenario, "sourceDigest")?,
            "source digest preimage",
        )?;
        validate_sql_arguments(scenario.get("source").ok_or("source")?)?;
        let policy_bytes = b64(scenario, "policyBytes")?;
        assert_ok(
            !String::from_utf8_lossy(&policy_bytes).contains("policyCid"),
            "policy self-reference",
        )?;
        assert_ok(
            cid(&policy_bytes) == text(scenario, "policyCid")?,
            "policy CID mismatch",
        )?;
        assert_ok(
            serde_json::from_slice::<Value>(&policy_bytes).map_err(|error| error.to_string())?
                == *scenario.get("policy").ok_or("policy")?,
            "policy bytes/object mismatch",
        )?;
        validate_message_schema("policy", scenario.get("policy").ok_or("policy")?, kind)?;
        let sealed = b64(scenario, "sealedBlob")?;
        assert_ok(
            cid(&sealed) == text(scenario, "shareCid")?,
            "share CID mismatch",
        )?;
        b64_string(
            scenario.get("envelopeKey").ok_or("envelope key")?,
            Some(32),
            "envelope key",
        )?;
        valid_cid(scenario.get("shareCid").ok_or("share CID")?, "share CID")?;
        valid_cid(scenario.get("policyCid").ok_or("policy CID")?, "policy CID")?;
        valid_cid(
            scenario.get("delegationCid").ok_or("delegation CID")?,
            "delegation CID",
        )?;
        let authority_material = scenario
            .get("authorityMaterial")
            .ok_or("authority material")?;
        assert_ok(
            text(scenario, "authorityMaterialHandle")?
                == map_text(
                    authority_material
                        .as_object()
                        .ok_or("authority material object")?,
                    "handle",
                )?,
            "authority handle",
        )?;
        assert_ok(
            digest(jcs(authority_material)?.as_bytes())
                == text(scenario, "authorityMaterialDigest")?,
            "authority material digest",
        )?;
        validate_message_schema("authorityMaterial", authority_material, kind)?;
        valid_share_id(scenario.get("shareId").ok_or("share ID")?, "share ID")?;
        b64_string(
            scenario.get("reportAbuseToken").ok_or("abuse token")?,
            Some(16),
            "abuse token",
        )?;
        b64_string(
            scenario.get("sdJwtSalt").ok_or("SD-JWT salt")?,
            Some(16),
            "SD-JWT salt",
        )?;
        let enrollment = scenario.get("enrollment").ok_or("enrollment")?;
        validate_node_enrollment(enrollment, &domains)?;
        validate_message_schema(
            "envelope",
            scenario.get("envelope").ok_or("envelope")?,
            kind,
        )?;
        validate_invite_authorization(scenario.get("authorization").ok_or("authorization")?, kind)?;
        let artifacts = array(scenario, "artifacts")?;
        assert_ok(artifacts.len() == 9, "signed artifact count")?;
        let mut artifact_names = Vec::new();
        for artifact in artifacts {
            let name = text(artifact, "name")?;
            assert_ok(
                !artifact_names.iter().any(|seen| seen == name),
                "signed artifact IDs unique",
            )?;
            artifact_names.push(name.to_string());
            verify_artifact(artifact, name, domains_map, enrollment)?;
        }
        let policy_artifact = artifact_named(scenario, "policy")?;
        assert_ok(
            text(policy_artifact, "signerDid")?
                == text(artifact_message(scenario, "policy")?, "issuerDid")?,
            "policy signer/issuer binding",
        )?;
        assert_ok(
            text(artifact_named(scenario, "envelope")?, "signerDid")?
                == text(artifact_message(scenario, "policy")?, "issuerDid")?,
            "envelope signer/policy issuer binding",
        )?;
        for name in ["holderBinding", "policyPresentation", "readInvocation"] {
            assert_ok(
                text(artifact_named(scenario, name)?, "signerDid")?
                    == text(artifact_message(scenario, name)?, "holderDid")?,
                "holder signer binding",
            )?;
        }
        for name in ["policyChallenge", "policySession"] {
            assert_ok(
                text(artifact_named(scenario, name)?, "signerDid")?
                    == text(enrollment, "nodeAudience")?,
                "node signer binding",
            )?;
        }
        assert_ok(
            scenario.get("authorization")
                == Some(artifact_message(scenario, "inviteAuthorization")?),
            "authorization artifact/object mismatch",
        )?;
        assert_ok(
            scenario.get("policy") == Some(artifact_message(scenario, "policy")?),
            "policy artifact/object mismatch",
        )?;
        let mut unsigned_envelope = scenario.get("envelope").ok_or("envelope")?.clone();
        unsigned_envelope
            .as_object_mut()
            .ok_or("envelope object")?
            .remove("signature");
        assert_ok(
            &unsigned_envelope == artifact_message(scenario, "envelope")?,
            "envelope artifact/object mismatch",
        )?;
        for required in [
            "policy",
            "envelope",
            "inviteAuthorization",
            "holderBinding",
            "policyChallenge",
            "policyPresentation",
            "policySession",
            "readInvocation",
            "authorityMaterial",
        ] {
            assert_ok(
                artifact_names.iter().any(|name| name == required),
                "signed artifact set",
            )?;
        }
        let preimages = object(scenario, "preimages")?;
        for required in [
            "claimRedeemRequest",
            "claimRedeemOtpRequest",
            "policyChallengeResponse",
            "policySessionResponse",
            "claimChallengeResponse",
        ] {
            assert_ok(
                preimages.get(required).is_some(),
                "endpoint preimage matrix",
            )?;
        }
        for (name, preimage) in preimages {
            let preimage_object = exact_object(
                preimage,
                &["body", "jcs", "digest"],
                &[],
                "endpoint preimage",
            )?;
            let body = map_value(preimage_object, "body", "endpoint preimage")?;
            let canonical = jcs(body)?;
            assert_ok(
                canonical == text(preimage, "jcs")?
                    && digest(canonical.as_bytes()) == text(preimage, "digest")?,
                &format!("preimage mismatch: {name}"),
            )?;
            validate_endpoint_body(name, body, scenario, enrollment, &issuer_key)?;
        }
        let signed_preimages = object(scenario, "signedBytePreimages")?;
        for artifact in artifacts {
            let name = text(artifact, "name")?;
            let frozen = signed_preimages
                .get(name)
                .ok_or("signed preimage missing")?;
            assert_ok(
                text(frozen, "domain")? == text(artifact, "domain")?
                    && text(frozen, "jcs")? == text(artifact, "jcs")?
                    && text(frozen, "digest")? == text(artifact, "signedBytesDigest")?,
                "signed preimage drift",
            )?;
        }
        proof_matches(
            preimages
                .get("policyChallengeResponse")
                .and_then(|preimage| preimage.get("body"))
                .ok_or("challenge response")?,
            artifacts
                .iter()
                .find(|artifact| text(artifact, "name").ok() == Some("policyChallenge"))
                .ok_or("challenge artifact")?,
            enrollment,
            "challenge response proof",
        )?;
        proof_matches(
            preimages
                .get("policySessionResponse")
                .and_then(|preimage| preimage.get("body"))
                .ok_or("session response")?,
            artifacts
                .iter()
                .find(|artifact| text(artifact, "name").ok() == Some("policySession"))
                .ok_or("session artifact")?,
            enrollment,
            "session response proof",
        )?;
        validate_sd_jwt(scenario, &issuer_key)?;
        validate_jti_replay_bindings(scenario)?;
        validate_cross_equations(scenario)?;
    }
    Ok(())
}
fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../");
    verify(&root).unwrap_or_else(|error| panic!("email-claim-v1 rust verifier failed: {error}"));
    println!("email-claim-v1 rust verifier: PASS");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cross_language_fixture() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../");
        verify(&root).unwrap();
    }
}
