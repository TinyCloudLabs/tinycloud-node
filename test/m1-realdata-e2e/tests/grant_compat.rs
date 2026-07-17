use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command,
};

use anyhow::{Context, Result};
use serde_json::Value;
use tempfile::TempDir;
use tinycloud_auth::authorization::{HeaderEncode, TinyCloudDelegation};
use tinycloud_core::hash::hash;

const FROZEN_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/grant-output");
const VECTOR_FILES: [&str; 5] = [
    "accept.json",
    "audit-reject.json",
    "node-import-reject.json",
    "node-invocation-reject.json",
    "producer-reject.json",
];
const DEFAULT_INSTANT: i64 = 1_783_684_800;

#[test]
fn frozen_plane_has_native_identity_shape_and_layer_partition() -> Result<()> {
    let package = load_package(Path::new(FROZEN_DIR))?;
    let mut all = BTreeSet::new();
    let mut node = BTreeSet::new();
    let mut skipped = BTreeSet::new();

    for document in package.values() {
        for case in document["cases"].as_array().context("cases array")? {
            let name = case["case"].as_str().context("case identity")?.to_string();
            assert!(all.insert(name.clone()), "duplicate case identity {name}");
            match case["enforcementLayer"].as_str().context("layer")? {
                "node-import" | "node-invocation" => {
                    node.insert(name);
                }
                "producer/engine" | "audit" => {
                    skipped.insert(name);
                }
                other => panic!("unrecognized enforcement layer {other}"),
            }
            if let Some(ucan) = case.get("ucan") {
                assert_ucan_identity(ucan)?;
            }
            if let Some(portable) = case.get("portableDelegation") {
                let encoded = portable["encoded"].as_str().context("portable encoded")?;
                assert_eq!(native_cid(encoded), portable["delegationId"]);
            }
        }
    }

    let skip: Value = serde_json::from_str(&fs::read_to_string(
        Path::new(FROZEN_DIR).join("SKIP_MANIFEST.json"),
    )?)?;
    let declared = skip["skippedCases"]
        .as_array()
        .context("skippedCases")?
        .iter()
        .map(|value| value.as_str().context("skip identity").map(str::to_string))
        .collect::<Result<BTreeSet<_>>>()?;
    assert_eq!(
        declared, skipped,
        "m1-g-07 skip ownership must be exhaustive"
    );
    assert_eq!(all.len(), 27);
    assert_eq!(node.len(), 13);
    assert_eq!(skipped.len(), 14);

    let accept = &package["accept.json"];
    let parent = &accept["parentFormatVector"];
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(
        parent["dagCborBase64Url"]
            .as_str()
            .context("parent bytes")?,
    )?;
    assert_eq!(hash(&bytes).to_cid(0x55).to_string(), parent["expectedCid"]);
    let mut parent_header = parent["dagCborBase64Url"]
        .as_str()
        .context("parent header")?
        .to_string();
    while parent_header.len() % 4 != 0 {
        parent_header.push('=');
    }
    let (delegation, decoded) = TinyCloudDelegation::decode(&parent_header)?;
    assert!(matches!(delegation, TinyCloudDelegation::Cacao(_)));
    assert_eq!(decoded, bytes);
    Ok(())
}

#[test]
fn generator_default_instant_is_the_cross_plane_byte_anchor() -> Result<()> {
    let output = TempDir::new()?;
    run_generator(DEFAULT_INSTANT, output.path())?;
    for file in VECTOR_FILES {
        assert_eq!(
            fs::read(output.path().join(file))?,
            fs::read(Path::new(FROZEN_DIR).join(file))?,
            "default-instant regeneration drifted for {file}"
        );
    }
    Ok(())
}

#[test]
fn live_plane_semantically_corresponds_to_every_frozen_case() -> Result<()> {
    let output = TempDir::new()?;
    run_generator(chrono::Utc::now().timestamp(), output.path())?;
    let frozen = load_package(Path::new(FROZEN_DIR))?;
    let live = load_package(output.path())?;
    for file in VECTOR_FILES {
        let frozen_cases = cases_by_name(&frozen[file])?;
        let live_cases = cases_by_name(&live[file])?;
        assert_eq!(
            frozen_cases.keys().collect::<Vec<_>>(),
            live_cases.keys().collect::<Vec<_>>()
        );
        for (name, frozen_case) in frozen_cases {
            let mut frozen_normalized = frozen_case.clone();
            let mut live_normalized = live_cases[&name].clone();
            normalize_time_derived(&mut frozen_normalized);
            normalize_time_derived(&mut live_normalized);
            assert_eq!(
                frozen_normalized, live_normalized,
                "semantic drift in {name}"
            );
        }
    }
    Ok(())
}

fn run_generator(instant: i64, output: &Path) -> Result<()> {
    let status = Command::new("python3")
        .arg(Path::new(FROZEN_DIR).join("generate.py"))
        .arg("--at-instant")
        .arg(instant.to_string())
        .arg("--output-dir")
        .arg(output)
        .status()
        .context("run pinned m1-g-06b generator")?;
    anyhow::ensure!(status.success(), "pinned generator failed: {status}");
    Ok(())
}

fn load_package(directory: &Path) -> Result<BTreeMap<&'static str, Value>> {
    VECTOR_FILES
        .into_iter()
        .map(|file| {
            let value = serde_json::from_str(&fs::read_to_string(directory.join(file))?)?;
            Ok((file, value))
        })
        .collect()
}

fn cases_by_name(document: &Value) -> Result<BTreeMap<String, Value>> {
    document["cases"]
        .as_array()
        .context("cases array")?
        .iter()
        .map(|case| {
            Ok((
                case["case"].as_str().context("case")?.to_string(),
                case.clone(),
            ))
        })
        .collect()
}

fn assert_ucan_identity(ucan: &Value) -> Result<()> {
    let encoded = ucan["encoded"].as_str().context("ucan encoded")?;
    assert_eq!(encoded.split('.').count(), 3);
    assert_eq!(native_cid(encoded), ucan["delegationId"]);
    let (delegation, bytes) = TinyCloudDelegation::decode(encoded)?;
    assert!(matches!(delegation, TinyCloudDelegation::Ucan(_)));
    assert_eq!(bytes, encoded.as_bytes());
    Ok(())
}

fn native_cid(encoded: &str) -> String {
    hash(encoded.as_bytes()).to_cid(0x55).to_string()
}

fn normalize_time_derived(value: &mut Value) {
    const OMIT: &[&str] = &[
        "encoded",
        "signingInputAscii",
        "signatureHex",
        "delegationId",
        "delegationIdBytesHex",
        "expectedDelegationId",
        "expectedDelegationIdBytesHex",
        "expectedCid",
        "expectedCidBytesHex",
        "dagCborBase64Url",
        "dagCborHex",
        "signatureHex",
        "siweMessage",
        "recapResource",
        "recapJcsUtf8Hex",
        "issuedAt",
        "expiresAt",
        "fixedInstantEpochSeconds",
        "validationTimeEpochSeconds",
        "invocationTimeEpochSeconds",
        "parentExpiresAtEpochSeconds",
        "nbf",
        "exp",
        "iat",
        "notBefore",
        "ceilings",
        "p",
        "s",
        "cacao",
        "portableDelegation",
        "issuanceRecord",
        "ledgerRecord",
        "ledgerRecords",
        "importedDelegationId",
        "configuredParentCid",
        "parentCid",
        "prf",
    ];
    match value {
        Value::Object(map) => {
            map.retain(|key, _| {
                let lower = key.to_ascii_lowercase();
                !OMIT.contains(&key.as_str())
                    && !lower.ends_with("cid")
                    && !lower.ends_with("cids")
                    && !key.ends_with("EpochSeconds")
            });
            for child in map.values_mut() {
                normalize_time_derived(child);
            }
        }
        Value::Array(values) => values.iter_mut().for_each(normalize_time_derived),
        _ => {}
    }
}

use base64::Engine as _;
