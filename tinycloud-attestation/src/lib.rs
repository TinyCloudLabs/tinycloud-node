//! Offline Intel DCAP verification with a pinned dstack deployment policy.
//!
//! `verify` is the only attestation acceptance entry point. It authenticates the
//! quote and supplied collateral against Intel's production trust root, checks
//! collateral at the caller's trusted current Unix time, then applies policy.
//! No collateral is fetched over the network. Historical timestamps belong only
//! in deterministic recorded-vector tests, never in a production caller.
//!
//! All policy measurements are hex bytes (an optional `0x` prefix is accepted).
//! `kms_id` is the KMS root CA's DER SubjectPublicKeyInfo encoded as hex, as
//! measured by dstack's `{"name":"kms","id":"<SPKI hex>"}` event. It is
//! **not** the string `kms`, a KMS URL, app ID, or a public-key hash. Pin the
//! independently established intended KMS SPKI; do not copy an untrusted target's
//! claimed identity into policy. Empty/absent/non-KMS provider identities fail.
//!
//! dstack measures app-id/compose-hash before boot-mr-done, then key-provider
//! after boot-mr-done and before system-ready. Every RTMR3 event is reconstructed
//! and SHA384-replayed, including unknown event names and events after readiness.
//! RTMR0-2 are pinned directly to the authenticated quote, not reconstructed
//! from the incomplete runtime log. See tests/fixtures/provenance.json for the
//! recorded fixture's limitations and the source of the provider representation.

use anyhow::{ensure, Context, Result};
use dcap_qvl::quote::TDReport10;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

const RUNTIME_EVENT_TYPE: u32 = 0x08000001;

/// An event in dstack's event-log JSON. Missing version means version 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub imr: u32,
    pub event_type: u32,
    pub digest: String,
    pub event: String,
    pub event_payload: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage: Option<String>,
}

/// Public quote, event log and offline Intel collateral; contains no root keys.
/// Collateral byte fields use dcap-qvl's hex-string JSON representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBundle {
    pub quote: String,
    pub event_log: Vec<Event>,
    pub collateral: dcap_qvl::QuoteCollateralV3,
}

/// Independently pinned deployment identity and OS measurements.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationPolicy {
    /// Nonempty app ID hex, compared as bytes to the measured event.
    pub app_id: String,
    /// Nonempty allowlist of 32-byte SHA256 compose measurements in hex.
    pub compose_hashes: Vec<String>,
    /// Nonempty KMS root CA SubjectPublicKeyInfo DER hex; see crate docs.
    pub kms_id: String,
    /// 48-byte MRTD hex.
    pub mrtd: String,
    /// 48-byte RTMR0 hex.
    pub rtmr0: String,
    /// 48-byte RTMR1 hex.
    pub rtmr1: String,
    /// 48-byte RTMR2 hex.
    pub rtmr2: String,
}

/// Accept only a cryptographically authenticated, UpToDate, non-debug TDX quote
/// that satisfies every pin and the exact 64-byte REPORTDATA binding.
///
/// `now` MUST be the caller's trusted current Unix time (seconds). It controls
/// Intel certificate/CRL and signed collateral validity checks. Callers must not
/// accept a target-provided timestamp. This function exposes no verification
/// bypass, alternate trust root, permissive TCB allowlist, or verified claims
/// that could be constructed separately from successful quote authentication.
pub fn verify(
    bundle: &AttestationBundle,
    policy: &AttestationPolicy,
    expected_report_data: &[u8; 64],
    now: u64,
) -> Result<()> {
    let verified = authenticate(bundle, now)?;
    let report = verified
        .report
        .as_td10()
        .context("a TDX report is required")?;
    verify_policy(
        &verified.status,
        report,
        &bundle.event_log,
        policy,
        expected_report_data,
    )
}

fn authenticate(bundle: &AttestationBundle, now: u64) -> Result<dcap_qvl::verify::VerifiedReport> {
    let quote = decode_hex(&bundle.quote, "quote")?;
    // The pinned dependency's production verifier uses Intel's embedded root,
    // enforces signature chains, revocation and freshness, and disallows debug
    // and service TDs. Network/report and dangerous override features are off.
    dcap_qvl::verify::verify(&quote, &bundle.collateral, now).context("DCAP authentication failed")
}

fn verify_policy(
    status: &str,
    report: &TDReport10,
    events: &[Event],
    policy: &AttestationPolicy,
    expected_report_data: &[u8; 64],
) -> Result<()> {
    ensure!(status == "UpToDate", "TCB status must be UpToDate");
    ensure!(
        report.td_attributes[0] & 1 == 0,
        "TDX debug attribute is forbidden"
    );
    ensure!(
        report.report_data == *expected_report_data,
        "REPORTDATA binding mismatch"
    );
    for (name, expected, actual) in [
        ("MRTD", &policy.mrtd, &report.mr_td),
        ("RTMR0", &policy.rtmr0, &report.rt_mr0),
        ("RTMR1", &policy.rtmr1, &report.rt_mr1),
        ("RTMR2", &policy.rtmr2, &report.rt_mr2),
    ] {
        ensure!(
            decode_fixed::<48>(expected, name)? == *actual,
            "{name} pin mismatch"
        );
    }
    ensure!(
        replay_event_log(events)? == report.rt_mr3,
        "event log does not match authenticated RTMR3"
    );

    let boot_done = unique_event(events, "boot-mr-done")?;
    let ready = unique_event(events, "system-ready")?;
    ensure!(
        boot_done < ready,
        "boot completion must precede system readiness"
    );
    let app = unique_event(events, "app-id")?;
    let compose = unique_event(events, "compose-hash")?;
    let provider = unique_event(events, "key-provider")?;
    ensure!(
        app < boot_done && compose < boot_done,
        "app and compose must precede boot completion"
    );
    ensure!(
        boot_done < provider && provider < ready,
        "KMS provider must follow boot completion and precede readiness"
    );

    let expected_app = decode_hex(&policy.app_id, "app ID policy")?;
    ensure!(!expected_app.is_empty(), "app ID policy cannot be empty");
    ensure!(
        decode_payload(&events[app])? == expected_app,
        "app ID pin mismatch"
    );
    ensure!(
        !policy.compose_hashes.is_empty(),
        "compose hash policy cannot be empty"
    );
    let measured_compose = decode_fixed::<32>(&events[compose].event_payload, "compose event")?;
    let mut compose_matches = false;
    for allowed in &policy.compose_hashes {
        compose_matches |= decode_fixed::<32>(allowed, "compose policy")? == measured_compose;
    }
    ensure!(compose_matches, "compose hash pin mismatch");

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct KeyProvider {
        name: String,
        id: String,
    }
    let provider_payload = decode_payload(&events[provider])?;
    let provider: KeyProvider = serde_json::from_slice(&provider_payload)
        .context("KMS provider payload must contain its name and identity")?;
    ensure!(
        provider.name == "kms",
        "an authenticated KMS provider is required"
    );
    let expected_kms = decode_hex(&policy.kms_id, "KMS identity policy")?;
    let measured_kms = decode_hex(&provider.id, "KMS event identity")?;
    ensure!(
        !expected_kms.is_empty() && !measured_kms.is_empty(),
        "KMS identity cannot be empty"
    );
    ensure!(measured_kms == expected_kms, "KMS identity pin mismatch");
    Ok(())
}

fn unique_event(events: &[Event], name: &str) -> Result<usize> {
    let mut matching = events
        .iter()
        .enumerate()
        .filter(|(_, event)| event.imr == 3 && event.event == name);
    let (index, _) = matching
        .next()
        .with_context(|| format!("missing {name} event"))?;
    ensure!(matching.next().is_none(), "duplicate {name} event");
    Ok(index)
}

fn replay_event_log(events: &[Event]) -> Result<[u8; 48]> {
    ensure!(!events.is_empty(), "event log cannot be empty");
    let mut register = [0; 48];
    let mut runtime_events = 0;
    for event in events {
        ensure!(event.imr <= 3, "invalid event IMR");
        if event.imr != 3 {
            // Firmware logs may contain other digest sizes and incomplete data.
            // The authenticated quote's RTMR0-2 are pinned separately above.
            continue;
        }
        runtime_events += 1;
        ensure!(
            event.event_type == RUNTIME_EVENT_TYPE,
            "unsupported runtime event type"
        );
        let digest = runtime_digest(event)?;
        if !event.digest.is_empty() {
            ensure!(
                decode_fixed::<48>(&event.digest, "runtime digest")? == digest,
                "runtime digest does not bind event contents"
            );
        }
        let mut hasher = Sha384::new();
        hasher.update(register);
        hasher.update(digest);
        register = hasher.finalize().into();
    }
    ensure!(runtime_events > 0, "event log contains no RTMR3 events");
    Ok(register)
}

fn runtime_digest(event: &Event) -> Result<[u8; 48]> {
    let payload = decode_payload(event)?;
    match event.version.unwrap_or(1) {
        1 => {
            let mut hasher = Sha384::new();
            hasher.update(RUNTIME_EVENT_TYPE.to_le_bytes());
            hasher.update(b":");
            hasher.update(event.event.as_bytes());
            hasher.update(b":");
            hasher.update(payload);
            Ok(hasher.finalize().into())
        }
        2 => {
            // Struct field order is deliberate: exactly JS JSON.stringify's
            // { name, payload, type } order, not a map's configurable ordering.
            #[derive(Serialize)]
            struct Preimage<'a> {
                name: &'a str,
                payload: String,
                #[serde(rename = "type")]
                event_type: u32,
            }
            let canonical = serde_json::to_vec(&Preimage {
                name: &event.event,
                payload: hex::encode(payload),
                event_type: RUNTIME_EVENT_TYPE,
            })?;
            let preimage = event
                .preimage
                .as_ref()
                .context("version 2 event requires a preimage")?;
            ensure!(
                decode_hex(preimage, "runtime preimage")? == canonical,
                "runtime preimage is not canonical"
            );
            Ok(Sha384::digest(canonical).into())
        }
        _ => anyhow::bail!("unsupported dstack event-log version"),
    }
}

fn decode_payload(event: &Event) -> Result<Vec<u8>> {
    // Unlike policy/quote fields, runtime payloads follow dstack's unprefixed
    // complete-byte hex format. Rust strings already require valid UTF-8.
    hex::decode(&event.event_payload).context("runtime payload must be complete hex bytes")
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .with_context(|| format!("{label} must be complete hex bytes"))
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    hex::decode_to_slice(value.strip_prefix("0x").unwrap_or(value), &mut bytes)
        .with_context(|| format!("{label} must be {N} bytes of hex"))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
