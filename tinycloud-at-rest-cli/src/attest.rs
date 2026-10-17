//! Deciding whether a TEE's recovery key is safe to release a share to.
//!
//! A holder releases a share only to a recovery recipient that a genuine,
//! up-to-date, non-debug TDX quote binds to, from the exact measured
//! deployment the holder pinned in a trust policy. The steps follow
//! `docs/attestation.md` and the registry's dstack verifier:
//!
//! 1. DCAP: quote signature, PCK chain, CRLs, TCB info and QE identity, with
//!    collateral (`dcap-qvl`). TCB status must be in the policy's allow-list.
//! 2. TD attributes: the debug bit must be clear.
//! 3. MRTD and RTMR0-2 equal the pinned OS-image measurements.
//! 4. The dstack event log replays to the quoted RTMR3, and its `app-id` and
//!    `compose-hash` events equal the pinned values.
//! 5. REPORTDATA equals SHA-256 of the binding the holder recomputes from
//!    their own fresh nonce, the bundle's EFP and the recovery recipient.

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha384};
use tinycloud_at_rest_escrow::{
    binding_digest, recovery_binding, validate_nonce, EscrowBundle, RecoveryInfo,
};

/// Measurements a holder trusts, from a source independent of the node
/// being verified (the release's published measurements, Phala's dashboard
/// cross-checked by Sam). Hex, lowercase.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    /// dstack app id (20 bytes).
    pub app_id: String,
    /// SHA-256 of the deployed app-compose.json.
    pub compose_hash: String,
    /// dstack OS image measurements (48 bytes each).
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    /// Accepted DCAP TCB statuses. Default: only `UpToDate`.
    #[serde(default = "default_tcb_status")]
    pub allowed_tcb_status: Vec<String>,
}

fn default_tcb_status() -> Vec<String> {
    vec!["UpToDate".into()]
}

fn hex_exact(value: &str, bytes: usize, label: &str) -> Result<Vec<u8>> {
    ensure!(
        value.len() == bytes * 2
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{label} must be {bytes} bytes of lowercase hex"
    );
    Ok(hex::decode(value)?)
}

impl TrustPolicy {
    pub fn validate(&self) -> Result<()> {
        hex_exact(&self.app_id, 20, "trust policy app_id")?;
        hex_exact(&self.compose_hash, 32, "trust policy compose_hash")?;
        for (v, l) in [
            (&self.mrtd, "mrtd"),
            (&self.rtmr0, "rtmr0"),
            (&self.rtmr1, "rtmr1"),
            (&self.rtmr2, "rtmr2"),
        ] {
            hex_exact(v, 48, &format!("trust policy {l}"))?;
        }
        ensure!(
            !self.allowed_tcb_status.is_empty(),
            "trust policy allowed_tcb_status is empty"
        );
        Ok(())
    }
}

/// The fields of a DCAP-verified TD report this tool decides on.
#[derive(Clone, Debug)]
pub struct AttestedTd {
    pub tcb_status: String,
    pub td_attributes: [u8; 8],
    pub mr_td: [u8; 48],
    pub rtmr: [[u8; 48]; 4],
    pub report_data: [u8; 64],
}

/// Step 1: full DCAP verification of `quote` against `collateral` at `now`.
pub fn verify_quote(
    quote: &[u8],
    collateral: &dcap_qvl::QuoteCollateralV3,
    now_secs: u64,
) -> Result<AttestedTd> {
    let verified = dcap_qvl::verify::verify(quote, collateral, now_secs)
        .map_err(|e| anyhow!("TDX quote failed DCAP verification: {e}"))?;
    let td = verified
        .report
        .as_td10()
        .ok_or_else(|| anyhow!("quote is not a TDX quote"))?;
    Ok(AttestedTd {
        tcb_status: verified.status.clone(),
        td_attributes: td.td_attributes,
        mr_td: td.mr_td,
        rtmr: [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3],
        report_data: td.report_data,
    })
}

/// Fetch collateral for `quote` from a PCCS (default: Phala's).
pub async fn fetch_collateral(quote: &[u8], pccs_url: &str) -> Result<dcap_qvl::QuoteCollateralV3> {
    dcap_qvl::collateral::CollateralClient::with_default_http(pccs_url)
        .map_err(|e| anyhow!("PCCS client: {e}"))?
        .fetch(quote)
        .await
        .map_err(|e| anyhow!("fetching DCAP collateral from {pccs_url}: {e}"))
}

const RUNTIME_EVENT_TYPE: u32 = 0x0800_0001;

#[derive(Debug, Deserialize)]
struct Event {
    imr: u32,
    event_type: u32,
    #[serde(default)]
    digest: String,
    #[serde(default)]
    event: String,
    #[serde(default)]
    event_payload: String,
    #[serde(default)]
    version: Option<u32>,
    #[serde(default)]
    preimage: Option<String>,
}

fn runtime_event_digest(index: usize, e: &Event) -> Result<[u8; 48]> {
    let payload = hex::decode(&e.event_payload)
        .with_context(|| format!("runtime event {index} payload is not hex"))?;
    let preimage = match e.version.unwrap_or(1) {
        1 => {
            let mut p = RUNTIME_EVENT_TYPE.to_le_bytes().to_vec();
            p.push(b':');
            p.extend_from_slice(e.event.as_bytes());
            p.push(b':');
            p.extend_from_slice(&payload);
            p
        }
        2 => {
            // dstack v2: canonical JSON {"name","payload","type"}; the log
            // carries it and it must match exactly.
            let canonical = serde_json::json!({
                "name": e.event,
                "payload": hex::encode(&payload),
                "type": RUNTIME_EVENT_TYPE,
            })
            .to_string()
            .into_bytes();
            let given = e
                .preimage
                .as_deref()
                .ok_or_else(|| anyhow!("runtime event {index} has no preimage"))?;
            ensure!(
                hex::decode(given).ok().as_deref() == Some(canonical.as_slice()),
                "runtime event {index} preimage is not canonical"
            );
            canonical
        }
        _ => bail!("runtime event {index}: unsupported dstack event-log version"),
    };
    Ok(Sha384::digest(&preimage).into())
}

/// Replay the RTMR3 events of a dstack event log.
fn replay_rtmr3(events: &[Event]) -> Result<[u8; 48]> {
    let mut register = [0u8; 48];
    let mut runtime = 0usize;
    for (index, e) in events.iter().enumerate() {
        ensure!(e.imr <= 3, "event log entry {index} has an invalid IMR");
        if e.imr != 3 {
            continue;
        }
        runtime += 1;
        ensure!(
            e.event_type == RUNTIME_EVENT_TYPE,
            "runtime event {index} has an unsupported type"
        );
        let rebuilt = runtime_event_digest(index, e)?;
        // dstack's stripped log leaves runtime digests empty; the authenticated
        // value is rebuilt from the payload either way.
        if !e.digest.is_empty() {
            ensure!(
                hex::decode(&e.digest).ok().as_deref() == Some(rebuilt.as_slice()),
                "runtime event {index} digest does not bind its contents"
            );
        }
        let mut h = Sha384::new();
        h.update(register);
        h.update(rebuilt);
        register = h.finalize().into();
    }
    ensure!(runtime > 0, "dstack event log has no RTMR3 events");
    Ok(register)
}

/// The single `name` event, measured before `boot-mr-done`, must carry `expected`.
fn require_boot_event(events: &[Event], name: &str, expected: &str) -> Result<()> {
    let runtime: Vec<&Event> = events.iter().filter(|e| e.imr == 3).collect();
    let position = |n: &str| runtime.iter().position(|e| e.event == n);
    let count = |n: &str| runtime.iter().filter(|e| e.event == n).count();
    ensure!(
        count("boot-mr-done") == 1 && count("system-ready") == 1,
        "dstack boot markers must each appear once"
    );
    let boot_done = position("boot-mr-done").expect("counted");
    let system_ready = position("system-ready").expect("counted");
    ensure!(
        boot_done > 0 && system_ready > boot_done,
        "dstack boot event ordering is invalid"
    );
    ensure!(
        count(name) == 1,
        "dstack event log must contain exactly one {name} event"
    );
    let at = position(name).expect("counted");
    ensure!(
        at < boot_done,
        "{name} must be measured before boot completion"
    );
    ensure!(
        runtime[at].event_payload == expected,
        "{name} in the attested event log is {}, but the trust policy pins {expected}",
        runtime[at].event_payload
    );
    Ok(())
}

/// Smallest nonce accepted for freshness: 128 bits as base64url.
pub const MIN_NONCE_LEN: usize = 22;

/// Steps 2-5, plus agreement between the node's answer and the bundle.
/// `nonce` must be the one this holder generated for this request.
pub fn check_recovery(
    info: &RecoveryInfo,
    bundle: &EscrowBundle,
    nonce: &str,
    trust: &TrustPolicy,
    td: &AttestedTd,
) -> Result<()> {
    trust.validate()?;
    bundle.validate()?;
    validate_nonce(nonce)?;
    ensure!(
        nonce.len() >= MIN_NONCE_LEN,
        "nonce must be at least {MIN_NONCE_LEN} chars; use `tinycloud-at-rest nonce`"
    );
    let efp = bundle.fingerprint();
    ensure!(
        info.efp == efp && info.ark_id == bundle.ark_id && info.generation == bundle.generation,
        "the node's escrow ({}) is not the bundle you hold ({efp})",
        info.efp
    );

    // Step 5 first on the cheap side: the node's own binding must be the one
    // we expect, for our nonce. A reply made for another nonce is stale.
    let expected = recovery_binding(&info.recovery_recipient, &efp, nonce);
    ensure!(
        info.binding == expected,
        "the node's binding is not for your nonce: stale or replayed response; request a new one"
    );
    let digest = binding_digest(&expected);

    ensure!(
        trust.allowed_tcb_status.contains(&td.tcb_status),
        "TDX TCB status is {}, not one of {:?}",
        td.tcb_status,
        trust.allowed_tcb_status
    );
    ensure!(
        td.td_attributes[0] & 0x01 == 0,
        "the TD is a debug TD (TUD.DEBUG set); its memory is readable by the host"
    );
    for (got, want, label) in [
        (&td.mr_td, &trust.mrtd, "MRTD"),
        (&td.rtmr[0], &trust.rtmr0, "RTMR0"),
        (&td.rtmr[1], &trust.rtmr1, "RTMR1"),
        (&td.rtmr[2], &trust.rtmr2, "RTMR2"),
    ] {
        ensure!(
            hex::encode(got) == *want,
            "{label} is {}, but the trust policy pins {want}",
            hex::encode(got)
        );
    }

    let log = info
        .event_log
        .as_deref()
        .ok_or_else(|| anyhow!("the node sent no event log"))?;
    let events: Vec<Event> = serde_json::from_str(log).context("event log is not a JSON array")?;
    ensure!(
        replay_rtmr3(&events)? == td.rtmr[3],
        "event log does not replay to the quoted RTMR3"
    );
    require_boot_event(&events, "app-id", &trust.app_id)?;
    require_boot_event(&events, "compose-hash", &trust.compose_hash)?;

    let mut want_report = [0u8; 64];
    want_report[..32].copy_from_slice(&digest.0);
    ensure!(
        td.report_data == want_report,
        "the quote's REPORTDATA does not bind this recovery key and your nonce: replayed or foreign quote"
    );
    ensure!(
        info.binding_sha256 == digest,
        "binding_sha256 does not match binding"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tinycloud_at_rest_escrow::{Ark, ArkId, Digest32, HolderRecipient, RecoveryIdentity};

    const TDX_QUOTE: &[u8] = include_bytes!("../tests/fixtures/tdx_quote");
    const TDX_COLLATERAL: &[u8] = include_bytes!("../tests/fixtures/tdx_quote_collateral.json");
    const TDX_QUOTE_OUTDATED: &[u8] = include_bytes!("../tests/fixtures/tdx_quote_outdated");
    const TDX_COLLATERAL_OUTDATED: &[u8] =
        include_bytes!("../tests/fixtures/tdx_quote_outdated_collateral.json");
    // Inside every validity window of the fixture collateral (TCB info and QE
    // identity issued 2025-06-19 / 2026-02-18, valid 30 days).
    const FIXTURE_NOW: u64 = 1_750_377_600; // 2025-06-20T00:00:00Z
    const FIXTURE_NOW_OUTDATED: u64 = 1_771_459_200; // 2026-02-19T00:00:00Z

    const NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const APP_ID: &str = "1111111111111111111111111111111111111111";
    const COMPOSE: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn bundle() -> EscrowBundle {
        let holders: Vec<HolderRecipient> = ["a", "b", "c"]
            .into_iter()
            .map(|h| HolderRecipient {
                holder: h.into(),
                recipient: RecoveryIdentity::generate().recipient(),
            })
            .collect();
        EscrowBundle::create(&Ark::generate(), ArkId::generate(), 1, &holders).unwrap()
    }

    fn event(name: &str, payload: &str) -> serde_json::Value {
        serde_json::json!({
            "imr": 3, "event_type": RUNTIME_EVENT_TYPE, "digest": "",
            "event": name, "event_payload": payload,
        })
    }

    fn event_log(app_id: &str, compose: &str) -> String {
        serde_json::json!([
            {"imr": 0, "event_type": 1, "digest": "00", "event": "", "event_payload": ""},
            event("system-preparing", ""),
            event("app-id", app_id),
            event("compose-hash", compose),
            event("instance-id", "33"),
            event("boot-mr-done", ""),
            event("system-ready", ""),
        ])
        .to_string()
    }

    /// A consistent, passing scenario built on synthetic measurements.
    struct Scenario {
        bundle: EscrowBundle,
        info: RecoveryInfo,
        trust: TrustPolicy,
        td: AttestedTd,
    }

    fn scenario() -> Scenario {
        let bundle = bundle();
        let tee = RecoveryIdentity::generate();
        let binding = recovery_binding(&tee.recipient(), &bundle.fingerprint(), NONCE);
        let digest = binding_digest(&binding);
        let log = event_log(APP_ID, COMPOSE);
        let events: Vec<Event> = serde_json::from_str(&log).unwrap();
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&digest.0);
        let td = AttestedTd {
            tcb_status: "UpToDate".into(),
            td_attributes: [0; 8],
            mr_td: [0xa0; 48],
            rtmr: [
                [0xa1; 48],
                [0xa2; 48],
                [0xa3; 48],
                replay_rtmr3(&events).unwrap(),
            ],
            report_data,
        };
        let trust = TrustPolicy {
            app_id: APP_ID.into(),
            compose_hash: COMPOSE.into(),
            mrtd: hex::encode([0xa0; 48]),
            rtmr0: hex::encode([0xa1; 48]),
            rtmr1: hex::encode([0xa2; 48]),
            rtmr2: hex::encode([0xa3; 48]),
            allowed_tcb_status: default_tcb_status(),
        };
        let info = RecoveryInfo {
            mode: "dstack".into(),
            state: "unlocked".into(),
            ark_id: bundle.ark_id,
            generation: bundle.generation,
            efp: bundle.fingerprint(),
            canary_fp: bundle.canary_fp,
            recovery_recipient: tee.recipient(),
            binding: binding.clone(),
            binding_sha256: digest,
            quote: Some(String::new()),
            event_log: Some(log),
            shares_held: vec![],
        };
        Scenario {
            bundle,
            info,
            trust,
            td,
        }
    }

    fn check(s: &Scenario, nonce: &str) -> Result<()> {
        check_recovery(&s.info, &s.bundle, nonce, &s.trust, &s.td)
    }

    fn assert_refused(s: &Scenario, nonce: &str, needle: &str) {
        let err = check(s, nonce).expect_err("must refuse").to_string();
        assert!(err.contains(needle), "{err:?} lacks {needle:?}");
    }

    #[test]
    fn consistent_attestation_passes() {
        check(&scenario(), NONCE).unwrap();
    }

    #[test]
    fn stale_nonce_is_refused() {
        // The node answered for an older nonce; the holder checks with theirs.
        let s = scenario();
        assert_refused(
            &s,
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "not for your nonce",
        );
        assert_refused(&s, "short", "at least 22");
    }

    #[test]
    fn replayed_quote_with_other_report_data_is_refused() {
        // A genuine quote for a different binding, with the node's JSON
        // rewritten to name the attacker's recipient.
        let mut s = scenario();
        let attacker = RecoveryIdentity::generate().recipient();
        s.info.recovery_recipient = attacker.clone();
        s.info.binding = recovery_binding(&attacker, &s.bundle.fingerprint(), NONCE);
        s.info.binding_sha256 = binding_digest(&s.info.binding);
        assert_refused(&s, NONCE, "REPORTDATA does not bind");
    }

    #[test]
    fn wrong_measurements_are_refused() {
        let base = scenario();
        let mut s = scenario();
        s.td = base.td.clone();
        s.td.mr_td[0] ^= 1;
        s.info = base.info.clone();
        s.bundle = base.bundle.clone();
        assert_refused(&s, NONCE, "MRTD");

        for (i, label) in [(0usize, "RTMR0"), (1, "RTMR1"), (2, "RTMR2")] {
            let mut s = scenario();
            s.td.rtmr[i][47] ^= 1;
            assert_refused(&s, NONCE, label);
        }

        let mut s = scenario();
        s.td.rtmr[3][0] ^= 1;
        assert_refused(&s, NONCE, "replay to the quoted RTMR3");

        // Another app (its own consistent log and RTMR3) and another compose.
        for (app, compose, needle) in [
            (
                "9999999999999999999999999999999999999999",
                COMPOSE,
                "app-id",
            ),
            (
                APP_ID,
                "9999999999999999999999999999999999999999999999999999999999999999",
                "compose-hash",
            ),
        ] {
            let mut s = scenario();
            let log = event_log(app, compose);
            s.td.rtmr[3] =
                replay_rtmr3(&serde_json::from_str::<Vec<Event>>(&log).unwrap()).unwrap();
            s.info.event_log = Some(log);
            assert_refused(&s, NONCE, needle);
        }
    }

    #[test]
    fn debug_td_and_bad_tcb_status_are_refused() {
        let mut s = scenario();
        s.td.td_attributes[0] |= 1;
        assert_refused(&s, NONCE, "debug TD");
        let mut s = scenario();
        s.td.tcb_status = "OutOfDate".into();
        assert_refused(&s, NONCE, "TCB status");
    }

    #[test]
    fn node_escrow_must_match_the_holders_bundle() {
        let mut s = scenario();
        s.info.efp = Digest32([7; 32]);
        assert_refused(&s, NONCE, "not the bundle you hold");
    }

    #[test]
    fn tampered_event_log_is_refused() {
        let mut s = scenario();
        let mut events: Vec<serde_json::Value> =
            serde_json::from_str(s.info.event_log.as_deref().unwrap()).unwrap();
        events[2]["digest"] = serde_json::json!("00".repeat(48));
        s.info.event_log = Some(serde_json::Value::Array(events).to_string());
        assert_refused(&s, NONCE, "digest does not bind");
    }

    fn collateral(bytes: &[u8]) -> dcap_qvl::QuoteCollateralV3 {
        serde_json::from_slice(bytes).unwrap()
    }

    #[test]
    fn genuine_quote_verifies_but_is_refused_as_foreign() {
        // A real Intel-signed TDX quote passes DCAP, but its REPORTDATA binds
        // someone else's data, so it can't vouch for our recovery key.
        let td = verify_quote(TDX_QUOTE, &collateral(TDX_COLLATERAL), FIXTURE_NOW).unwrap();
        let mut s = scenario();
        s.trust.mrtd = hex::encode(td.mr_td);
        s.trust.rtmr0 = hex::encode(td.rtmr[0]);
        s.trust.rtmr1 = hex::encode(td.rtmr[1]);
        s.trust.rtmr2 = hex::encode(td.rtmr[2]);
        s.trust.allowed_tcb_status = vec![td.tcb_status.clone()];
        let log_rtmr3 = s.td.rtmr[3];
        s.td = td;
        s.td.rtmr[3] = log_rtmr3;
        assert_refused(&s, NONCE, "REPORTDATA does not bind");
    }

    #[test]
    fn forged_quote_fails_dcap() {
        // REPORTDATA, MRTD, and the ECDSA signature (after the 48-byte header,
        // 584-byte TD body and 4-byte signature length).
        for offset in [48 + 520, 48 + 136, 48 + 584 + 4 + 10] {
            let mut forged = TDX_QUOTE.to_vec();
            forged[offset] ^= 0x01;
            let err = verify_quote(&forged, &collateral(TDX_COLLATERAL), FIXTURE_NOW)
                .expect_err("forged quote must fail");
            assert!(err.to_string().contains("DCAP"), "{err}");
        }
    }

    #[test]
    fn quote_outside_collateral_validity_fails_dcap() {
        assert!(verify_quote(
            TDX_QUOTE,
            &collateral(TDX_COLLATERAL),
            FIXTURE_NOW + 10 * 365 * 86_400
        )
        .is_err());
    }

    #[test]
    fn outdated_platform_quote_is_refused() {
        // A real quote from a platform whose TCB level the collateral no
        // longer lists. DCAP refuses it outright.
        let err = verify_quote(
            TDX_QUOTE_OUTDATED,
            &collateral(TDX_COLLATERAL_OUTDATED),
            FIXTURE_NOW_OUTDATED,
        )
        .expect_err("outdated platform must be refused");
        assert!(err.to_string().contains("DCAP"), "{err}");
    }

    #[test]
    fn trust_policy_rejects_malformed_pins() {
        let mut t = scenario().trust;
        t.mrtd = "AB".repeat(48);
        assert!(t.validate().is_err());
        let mut t = scenario().trust;
        t.allowed_tcb_status.clear();
        assert!(t.validate().is_err());
        assert!(serde_json::from_str::<TrustPolicy>(r#"{"app_id":"x","extra":1}"#).is_err());
    }
}
