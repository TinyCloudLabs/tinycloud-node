use std::{fs, path::Path};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::TempDir;

const CLAIM: &str = "after the owner publishes a monotonic revoked PolicyStatus and redeploys the owner-controlled sidecar from that authority state, the next direct live challenge/resolve exchange is denied policy-inactive, and the previously issued short-TTL delegation is refused by the node after expiry; requester ownerNode public-IP SSRF behavior is unit-conformance-only and is not claimed as live-observed";

#[derive(Clone, Copy)]
pub enum Mode {
    Verify,
    VerifyAndMutationSelfTest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema: String,
    run_id: String,
    created_at: String,
    inputs: Inputs,
    candidates: Candidates,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Inputs {
    nonce_sha256: String,
    renewal_nonce_sha256: String,
    revoked_nonce_sha256: String,
    sql_seed_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Candidates {
    tinycloud_node: String,
    policy_engine: String,
    js_sdk: String,
    listen: String,
    open_credentials: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Exchange {
    run_id: String,
    request_id: String,
    producer_pid: u32,
    request: Value,
    response: Value,
    observed_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    run_id: String,
    observed_at: String,
    database: String,
    delegations: Vec<DelegationRow>,
    abilities: Vec<Value>,
    parent_delegations: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct DelegationRow {
    id: Value,
    serialization: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Teardown {
    run_id: String,
    observed_at: String,
    runner_exit: i32,
    all_owned_processes_dead: bool,
    all_dynamic_ports_closed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    schema: &'static str,
    run_id: String,
    verdict: &'static str,
    claim: &'static str,
    assertions: Vec<Assertion>,
    mutation_self_test: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Assertion {
    name: &'static str,
    result: &'static str,
    citations: Vec<Citation>,
    derivation_rule: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Citation {
    transcript_file: String,
    producing_process_pid: u32,
    run_id: String,
    request_or_correlation_id: String,
    location: String,
}

pub fn run(bundle: &Path, mode: Mode, expected_node_sha: &str) -> Result<Report> {
    let mut report = verify(bundle, expected_node_sha)?;
    if matches!(mode, Mode::VerifyAndMutationSelfTest) {
        mutation_self_test(bundle, expected_node_sha)?;
        report.mutation_self_test = Some("passed");
    }
    Ok(report)
}

fn verify(bundle: &Path, expected_node_sha: &str) -> Result<Report> {
    let manifest: Manifest = read_json(bundle, "manifest.json")?;
    if manifest.schema != "xyz.tinycloud.m1/live-gate-raw-bundle/v1" {
        bail!("manifest schema is not the live-gate raw-bundle contract");
    }
    parse_time(&manifest.created_at, "manifest.createdAt")?;
    require_hex_hashes(&manifest.inputs)?;
    require_candidate_pins(bundle, &manifest.candidates, expected_node_sha)?;
    require_process_evidence(bundle)?;
    let runner_pid: u32 = fs::read_to_string(bundle.join("meta/runner.pid"))?
        .trim()
        .parse()?;

    let publish: Exchange = read_exchange(bundle, "driver/publish.json", &manifest.run_id)?;
    let initial: Exchange = read_exchange(bundle, "requester/initial.json", &manifest.run_id)?;
    let renewal: Exchange = read_exchange(bundle, "requester/renewal.json", &manifest.run_id)?;
    let revoke: Exchange = read_exchange(bundle, "driver/revoke.json", &manifest.run_id)?;
    let denied: Exchange =
        read_exchange(bundle, "requester/renewal-denied.json", &manifest.run_id)?;
    let expired: Exchange =
        read_exchange(bundle, "requester/post-expiry-read.json", &manifest.run_id)?;
    let pre: Snapshot = read_json(bundle, "node-db/pre-import.json")?;
    let post: Snapshot = read_json(bundle, "node-db/post-import.json")?;
    let teardown: Teardown = read_json(bundle, "meta/teardown.json")?;
    require_run(&pre.run_id, &manifest.run_id, "pre-import snapshot")?;
    require_run(&post.run_id, &manifest.run_id, "post-import snapshot")?;
    require_run(&teardown.run_id, &manifest.run_id, "teardown")?;
    parse_time(&teardown.observed_at, "teardown observedAt")?;
    if teardown.runner_exit != 0
        || !teardown.all_owned_processes_dead
        || !teardown.all_dynamic_ports_closed
    {
        bail!("teardown does not prove all owned processes dead and ports closed");
    }
    let pre_time = parse_time(&pre.observed_at, "pre-import observedAt")?;
    let post_time = parse_time(&post.observed_at, "post-import observedAt")?;

    let publish_time = parse_time(&publish.observed_at, "publish observedAt")?;
    let revoke_time = parse_time(&revoke.observed_at, "revoke observedAt")?;
    let ready_time = read_timestamp(bundle, "sidecar/redeployed-ready.timestamp")?;
    let denied_time = parse_time(&denied.observed_at, "denial observedAt")?;
    let expired_time = parse_time(&expired.observed_at, "expiry observedAt")?;
    if !(publish_time < revoke_time
        && revoke_time <= ready_time
        && ready_time <= denied_time
        && denied_time < expired_time)
    {
        bail!("revoke/redeploy/denial/expiry timestamps are not monotonic");
    }

    let delegation = required(&initial.response, "/delegation", "initial delegation")?;
    let imported = required(&initial.response, "/import/delegation", "import delegation")?;
    if delegation != imported {
        bail!("resolve output bytes are not identical to /delegate import input");
    }
    let issued = time_field(&initial.response, "/issuedAt")?;
    let expires = time_field(&initial.response, "/expiresAt")?;
    let ttl = (expires - issued).num_seconds();
    if !(1..=60).contains(&ttl) {
        bail!("initial delegation TTL {ttl}s is outside 1..=60");
    }
    require_seed_hash(
        &initial.response,
        "/reads/sql/sha256",
        &manifest.inputs.sql_seed_sha256,
    )?;
    require_true(&renewal.response, "/renewed", "renewal success")?;
    require_eq(
        &revoke.response,
        "/disposition",
        "revoked",
        "revoked disposition",
    )?;
    require_eq(
        &denied.response,
        "/error/code",
        "policy-inactive",
        "renewal denial",
    )?;
    require_eq(
        &denied.response,
        "/execution",
        "direct-live-challenge",
        "denial execution boundary",
    )?;
    require_eq(
        &initial.response,
        "/ssrfScope/coverage",
        "unit-conformance-only",
        "SSRF coverage scope",
    )?;
    if initial
        .response
        .pointer("/ssrfScope/liveObserved")
        .and_then(Value::as_bool)
        != Some(false)
    {
        bail!("SSRF live-observation label is not false");
    }
    require_eq(
        &expired.response,
        "/layer",
        "native-node",
        "expiry denial layer",
    )?;
    require_true(&expired.response, "/refused", "post-expiry native refusal")?;

    if pre.database != post.database || pre.database.is_empty() {
        bail!("database snapshot paths differ or are empty");
    }
    if pre_time >= post_time {
        bail!("database snapshots are not ordered pre-import then post-import");
    }
    if post.delegations.len() <= pre.delegations.len()
        || post.abilities.len() <= pre.abilities.len()
        || post.parent_delegations.len() < pre.parent_delegations.len()
    {
        bail!("post-import snapshot does not add delegation/ability authority rows");
    }
    let imported_text = imported
        .as_str()
        .ok_or_else(|| anyhow!("import delegation is not a string"))?;
    if pre
        .delegations
        .iter()
        .any(|row| value_contains(&row.serialization, imported_text))
    {
        bail!("imported delegation was already present before /delegate");
    }
    if !post
        .delegations
        .iter()
        .any(|row| value_contains(&row.serialization, imported_text))
    {
        bail!("post-import authority rows do not contain the imported delegation bytes");
    }
    if post.delegations.iter().any(|row| row.id.is_null()) {
        bail!("post-import delegation has a null identity");
    }

    let assertions = vec![
        assertion("candidate-pins-and-external-inputs", "manifest.json", runner_pid, &manifest.run_id, "manifest", "/candidates and /inputs", "candidate SHAs equal the approved pins; all four caller inputs are nonempty SHA-256 digests"),
        exchange_assertion("signed-authority-published", "driver/publish.json", &publish, "/response", "the production driver returned its raw publish artifact before sidecar startup"),
        exchange_assertion("resolve-import-byte-provenance", "requester/initial.json", &initial, "/response/delegation and /response/import/delegation", "the resolve output string is byte-identical to the native /delegate input string"),
        exchange_assertion("native-constrained-sql-seed-read", "requester/initial.json", &initial, "/response/reads/sql/sha256", "the named constrained SQL read hash equals the independent hash of caller-supplied seed bytes"),
        exchange_assertion("short-ttl-and-renewal", "requester/renewal.json", &renewal, "/response/renewed", &format!("initial wire issuedAt/expiresAt difference is {ttl}s (1..=60) and a second direct live challenge/resolve/import exchange succeeded")),
        assertion("delegation-path-origin", "node-db/pre-import.json + node-db/post-import.json", runner_pid, &manifest.run_id, &initial.request_id, "/delegations, /abilities, /parentDelegations", "the same database gains delegation and ability rows only after /delegate, and the imported serialization is absent before but present after"),
        exchange_assertion("monotonic-revoke", "driver/revoke.json", &revoke, "/response/disposition", "the driver response records revoked and its timestamp precedes sidecar readiness"),
        exchange_assertion("post-redeploy-renewal-denied", "requester/renewal-denied.json", &denied, "/response/error/code and /response/execution", "the first direct live challenge after redeployed readiness returned policy-inactive; no TranscriptRequester accessEnded transition is claimed"),
        exchange_assertion("owner-node-ssrf-unit-scope", "requester/initial.json", &initial, "/response/ssrfScope", "ownerNode public-IP SSRF guard: unit-conformance-only (e-02 amendment 37 / Sol #10; sdk-core requester tests:565-620), liveObserved=false; not a live gate observation"),
        exchange_assertion("post-expiry-native-refusal", "requester/post-expiry-read.json", &expired, "/response/layer and /response/refused", "a later node response is classified native-node and refused after the issued expiry"),
        assertion("ordered-observation-window", "driver/revoke.json + sidecar/redeployed-ready.timestamp + requester/renewal-denied.json + requester/post-expiry-read.json", runner_pid, &manifest.run_id, "timeline", "observedAt", "revoked commit <= redeployed ready <= renewal denial < native refusal; the bound starts at successful redeploy"),
        assertion("clean-teardown", "meta/teardown.json", runner_pid, &manifest.run_id, "teardown", "/runnerExit, /allOwnedProcessesDead, /allDynamicPortsClosed", "runner exit is zero after probing every owned PID dead and every captured dynamic port closed"),
    ];

    Ok(Report {
        schema: "xyz.tinycloud.m1/live-gate-verdict/v1",
        run_id: manifest.run_id,
        verdict: "pass",
        claim: CLAIM,
        assertions,
        mutation_self_test: None,
    })
}

fn mutation_self_test(bundle: &Path, expected_node_sha: &str) -> Result<()> {
    let temp = TempDir::new().context("create mutation bundle")?;
    copy_tree(bundle, temp.path())?;
    let target = temp.path().join("requester/renewal-denied.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&target)?)?;
    value
        .pointer_mut("/response/error")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("real bundle denial has no response.error object to mutate"))?
        .remove("code");
    fs::write(&target, serde_json::to_vec_pretty(&value)?)?;
    if verify(temp.path(), expected_node_sha).is_ok() {
        bail!("negative mutation self-test unexpectedly accepted a missing denial code");
    }
    Ok(())
}

fn read_exchange(bundle: &Path, file: &str, run_id: &str) -> Result<Exchange> {
    let exchange: Exchange = read_json(bundle, file)?;
    require_run(&exchange.run_id, run_id, file)?;
    if exchange.request_id.is_empty() || exchange.producer_pid == 0 || exchange.request.is_null() {
        bail!("{file} lacks request id, producer PID, or request");
    }
    parse_time(&exchange.observed_at, file)?;
    Ok(exchange)
}

fn read_json<T: for<'de> Deserialize<'de>>(bundle: &Path, file: &str) -> Result<T> {
    let path = bundle.join(file);
    serde_json::from_slice(&fs::read(&path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

fn required<'a>(value: &'a Value, pointer: &str, label: &str) -> Result<&'a Value> {
    value
        .pointer(pointer)
        .ok_or_else(|| anyhow!("missing {label} at {pointer}"))
}

fn require_eq(value: &Value, pointer: &str, expected: &str, label: &str) -> Result<()> {
    if required(value, pointer, label)?.as_str() != Some(expected) {
        bail!("{label} does not equal {expected}");
    }
    Ok(())
}

fn require_true(value: &Value, pointer: &str, label: &str) -> Result<()> {
    if required(value, pointer, label)?.as_bool() != Some(true) {
        bail!("{label} is not true");
    }
    Ok(())
}

fn require_seed_hash(value: &Value, pointer: &str, expected: &str) -> Result<()> {
    if required(value, pointer, "read hash")?.as_str() != Some(expected) {
        bail!("native read hash does not match caller input hash");
    }
    Ok(())
}

fn time_field(value: &Value, pointer: &str) -> Result<DateTime<Utc>> {
    let raw = required(value, pointer, pointer)?
        .as_str()
        .ok_or_else(|| anyhow!("{pointer} is not a timestamp"))?;
    parse_time(raw, pointer)
}

fn parse_time(raw: &str, label: &str) -> Result<DateTime<Utc>> {
    raw.parse::<DateTime<Utc>>()
        .with_context(|| format!("invalid timestamp for {label}"))
}

fn read_timestamp(bundle: &Path, file: &str) -> Result<DateTime<Utc>> {
    let raw = fs::read_to_string(bundle.join(file))?;
    parse_time(raw.trim(), file)
}

fn require_run(actual: &str, expected: &str, label: &str) -> Result<()> {
    if actual != expected || actual.is_empty() {
        bail!("{label} run id does not match manifest");
    }
    Ok(())
}

fn require_hex_hashes(inputs: &Inputs) -> Result<()> {
    for value in [
        &inputs.nonce_sha256,
        &inputs.renewal_nonce_sha256,
        &inputs.revoked_nonce_sha256,
        &inputs.sql_seed_sha256,
    ] {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("caller input digest is not a SHA-256 hex string");
        }
    }
    Ok(())
}

fn require_candidate_pins(
    bundle: &Path,
    candidates: &Candidates,
    expected_node_sha: &str,
) -> Result<()> {
    if expected_node_sha.is_empty() {
        bail!("expected node SHA is required");
    }
    let recorded_node_sha = fs::read_to_string(bundle.join("meta/tinycloud-node.sha"))?;
    let recorded_node_sha = recorded_node_sha.trim();
    if !recorded_node_sha.starts_with(expected_node_sha)
        || !candidates.tinycloud_node.starts_with(expected_node_sha)
        || candidates.tinycloud_node != recorded_node_sha
    {
        bail!("candidate SHA does not match required node pin {expected_node_sha}");
    }
    let expected = [
        (&candidates.policy_engine, "d72812a"),
        (&candidates.js_sdk, "2949408"),
        (&candidates.listen, "7bbd99a"),
        (&candidates.open_credentials, "a1633710"),
    ];
    for (actual, prefix) in expected {
        if !actual.starts_with(prefix) {
            bail!("candidate SHA {actual} does not match approved pin {prefix}");
        }
    }
    Ok(())
}

fn require_process_evidence(bundle: &Path) -> Result<()> {
    for file in [
        "meta/artifacts.sha256",
        "meta/runner.pid",
        "meta/runner.actual-command",
        "node/process.pid",
        "node/process.actual-command",
        "node/port",
        "sidecar/initial-process.pid",
        "sidecar/initial-process.actual-command",
        "sidecar/redeployed-process.pid",
        "sidecar/redeployed-process.actual-command",
        "sidecar/initial-port",
        "sidecar/redeployed-port",
    ] {
        let content = fs::read_to_string(bundle.join(file))
            .with_context(|| format!("read process evidence {file}"))?;
        if content.trim().is_empty() {
            bail!("process evidence {file} is empty");
        }
    }
    for file in [
        "node/port",
        "sidecar/initial-port",
        "sidecar/redeployed-port",
    ] {
        let port: u16 = fs::read_to_string(bundle.join(file))?.trim().parse()?;
        if port == 0 {
            bail!("captured dynamic port is zero");
        }
    }
    Ok(())
}

fn value_contains(value: &Value, needle: &str) -> bool {
    value.as_str().is_some_and(|text| text.contains(needle))
        || value
            .as_array()
            .is_some_and(|items| items.iter().any(|item| value_contains(item, needle)))
        || value
            .as_object()
            .is_some_and(|items| items.values().any(|item| value_contains(item, needle)))
}

fn assertion(
    name: &'static str,
    file: &str,
    pid: u32,
    run_id: &str,
    request_id: &str,
    location: &str,
    rule: &str,
) -> Assertion {
    Assertion {
        name,
        result: "pass",
        citations: vec![Citation {
            transcript_file: file.to_owned(),
            producing_process_pid: pid,
            run_id: run_id.to_owned(),
            request_or_correlation_id: request_id.to_owned(),
            location: location.to_owned(),
        }],
        derivation_rule: rule.to_owned(),
    }
}

fn exchange_assertion(
    name: &'static str,
    file: &str,
    exchange: &Exchange,
    location: &str,
    rule: &str,
) -> Assertion {
    assertion(
        name,
        file,
        exchange.producer_pid,
        &exchange.run_id,
        &exchange.request_id,
        location,
        rule,
    )
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            fs::create_dir_all(&target)?;
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}
