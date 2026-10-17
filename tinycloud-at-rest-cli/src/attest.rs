//! Deciding whether a TEE's recovery key is safe to release a share to.
//!
//! A holder releases a share only to a recovery recipient that a genuine,
//! up-to-date, non-debug TDX quote binds to, from the exact measured
//! deployment the holder pinned in a trust policy. The steps follow
//! `docs/attestation.md` and the registry's dstack verifier:
//!
//! 1. DCAP: quote signature, PCK chain, CRLs, TCB info and QE identity, with
//!    collateral (`dcap-qvl`). The TCB status is a fixed class: `UpToDate`
//!    passes; the hardening/configuration classes pass only if the policy
//!    allows them and pins every advisory ID; `OutOfDate*`, `TDRelaunch*`,
//!    `Revoked` and anything unknown never pass.
//! 2. TD attributes: the debug bit must be clear.
//! 3. MRTD and RTMR0-2 equal the pinned OS-image measurements.
//! 4. The dstack event log replays to the quoted RTMR3, and its `app-id` and
//!    `compose-hash` events equal the pinned values.
//! 5. REPORTDATA equals SHA-256 of the binding the holder recomputes from
//!    their own fresh nonce, the bundle's EFP and the recovery recipient.

use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use dcap_qvl::TcbStatus;
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha384};
use tinycloud_at_rest_escrow::{
    binding_digest, recovery_binding, validate_nonce, EscrowBundle, RecoveryInfo,
};

/// A TCB status a trust policy may accept. `OutOfDate*`, `TDRelaunchAdvised*`
/// and `Revoked` are deliberately not representable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AcceptedTcb {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
}

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
    /// Accepted TCB statuses. Default: only `UpToDate`.
    #[serde(default = "default_tcb")]
    pub allowed_tcb_status: Vec<AcceptedTcb>,
    /// Intel advisory IDs (e.g. `INTEL-SA-00837`) the holder accepts. Every
    /// advisory the quote's TCB level carries must be listed here.
    #[serde(default)]
    pub allowed_advisories: Vec<String>,
}

fn default_tcb() -> Vec<AcceptedTcb> {
    vec![AcceptedTcb::UpToDate]
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
        for id in &self.allowed_advisories {
            ensure!(
                id.starts_with("INTEL-SA-") && id.len() <= 32,
                "trust policy advisory {id:?} is not an INTEL-SA-… id"
            );
        }
        Ok(())
    }
}

/// The fields of a DCAP-verified TD report this tool decides on.
#[derive(Clone, Debug)]
pub struct AttestedTd {
    pub tcb_status: TcbStatus,
    pub advisory_ids: Vec<String>,
    pub td_attributes: [u8; 8],
    pub mr_td: [u8; 48],
    pub rtmr: [[u8; 48]; 4],
    pub report_data: [u8; 64],
}

impl AttestedTd {
    fn from_report(verified: &dcap_qvl::verify::VerifiedReport) -> Result<Self> {
        // dcap-qvl prints the enum variant name; anything else is refused.
        let tcb_status: TcbStatus =
            serde_json::from_value(serde_json::Value::String(verified.status.clone()))
                .map_err(|_| anyhow!("unknown TCB status {:?}", verified.status))?;
        let td = verified
            .report
            .as_td10()
            .ok_or_else(|| anyhow!("quote is not a TDX quote"))?;
        Ok(Self {
            tcb_status,
            advisory_ids: verified.advisory_ids.clone(),
            td_attributes: td.td_attributes,
            mr_td: td.mr_td,
            rtmr: [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3],
            report_data: td.report_data,
        })
    }
}

/// Step 1: full DCAP verification of `quote` against `collateral` at `now`.
pub fn verify_quote(
    quote: &[u8],
    collateral: &dcap_qvl::QuoteCollateralV3,
    now_secs: u64,
) -> Result<AttestedTd> {
    let verified = dcap_qvl::verify::verify(quote, collateral, now_secs)
        .map_err(|e| anyhow!("TDX quote failed DCAP verification: {e}"))?;
    AttestedTd::from_report(&verified)
}

/// The TCB decision. Returns a line to print on success.
pub fn check_tcb(td: &AttestedTd, trust: &TrustPolicy) -> Result<String> {
    let accepted = match td.tcb_status {
        TcbStatus::UpToDate => AcceptedTcb::UpToDate,
        TcbStatus::SWHardeningNeeded => AcceptedTcb::SWHardeningNeeded,
        TcbStatus::ConfigurationNeeded => AcceptedTcb::ConfigurationNeeded,
        TcbStatus::ConfigurationAndSWHardeningNeeded => {
            AcceptedTcb::ConfigurationAndSWHardeningNeeded
        }
        TcbStatus::OutOfDate
        | TcbStatus::OutOfDateConfigurationNeeded
        | TcbStatus::TDRelaunchAdvised
        | TcbStatus::TDRelaunchAdvisedConfigurationNeeded
        | TcbStatus::Revoked => bail!(
            "TDX TCB status is {} (advisories {:?}); this class is never accepted",
            td.tcb_status,
            td.advisory_ids
        ),
    };
    ensure!(
        trust.allowed_tcb_status.contains(&accepted),
        "TDX TCB status is {} (advisories {:?}), not one of {:?}",
        td.tcb_status,
        td.advisory_ids,
        trust.allowed_tcb_status
    );
    // A non-UpToDate class always comes with the advisories that caused it;
    // one without any is anomalous.
    ensure!(
        accepted == AcceptedTcb::UpToDate || !td.advisory_ids.is_empty(),
        "TDX TCB status {} carries no advisory IDs, which is anomalous; refused",
        td.tcb_status
    );
    let unpinned: Vec<&String> = td
        .advisory_ids
        .iter()
        .filter(|id| !trust.allowed_advisories.contains(id))
        .collect();
    ensure!(
        unpinned.is_empty(),
        "TDX TCB status {} carries advisories {unpinned:?} that the trust policy does not pin",
        td.tcb_status
    );
    Ok(format!(
        "TCB status {} with advisories {:?}",
        td.tcb_status, td.advisory_ids
    ))
}

/// Fetch collateral for `quote` from a PCCS (default: Phala's). Intel PCS
/// (`https://api.trustedservices.intel.com`) also works.
pub async fn fetch_collateral(quote: &[u8], pccs_url: &str) -> Result<dcap_qvl::QuoteCollateralV3> {
    let fetch = async {
        dcap_qvl::collateral::CollateralClient::with_default_http(pccs_url)
            .map_err(|e| anyhow!("PCCS client: {e}"))?
            .fetch(quote)
            .await
            .map_err(|e| anyhow!("fetching DCAP collateral from {pccs_url}: {e}"))
    };
    tokio::time::timeout(Duration::from_secs(60), fetch)
        .await
        .map_err(|_| anyhow!("fetching DCAP collateral from {pccs_url} timed out"))?
}

/// The issue/next-update window of the TCB info used, for the holder's record.
pub fn collateral_dates(collateral: &dcap_qvl::QuoteCollateralV3) -> String {
    let info: Result<dcap_qvl::TcbInfo, _> = serde_json::from_str(&collateral.tcb_info);
    match info {
        Ok(i) => format!(
            "TCB info issued {} (next update {}, evaluation data #{})",
            i.issue_date, i.next_update, i.tcb_evaluation_data_number
        ),
        Err(_) => "TCB info dates unavailable".into(),
    }
}

/// What the node answered must describe an attested TEE before anything
/// else is checked: `mode` dstack, a non-empty hex quote.
pub fn require_attested(info: &RecoveryInfo) -> Result<Vec<u8>> {
    ensure!(
        info.mode == "dstack",
        "the node is not in a TEE (mode {:?}); a share is only released to an attested TEE",
        info.mode
    );
    let quote = hex::decode(info.quote.as_deref().unwrap_or_default())
        .context("the node's quote is not hex")?;
    ensure!(!quote.is_empty(), "the node sent no TDX quote");
    Ok(quote)
}

/// What `verify-compose` found: each service's pinned image, plus the other
/// app-compose settings the hash covers.
#[derive(Debug)]
pub struct ComposeReport {
    pub images: Vec<(String, String)>,
    pub settings: Vec<String>,
}

/// `compose-hash` pins container images only if the compose file names each
/// image by digest. Check `app-compose.json` against the trust policy's
/// `compose_hash`, then parse its compose YAML strictly (see `compose.rs`).
pub fn check_app_compose(app_compose: &[u8], trust: &TrustPolicy) -> Result<ComposeReport> {
    let digest = hex::encode(Sha256::digest(app_compose));
    ensure!(
        digest == trust.compose_hash,
        "app-compose.json hashes to {digest}, but the trust policy pins compose_hash {}",
        trust.compose_hash
    );
    let doc: serde_json::Value =
        serde_json::from_slice(app_compose).context("app-compose.json is not JSON")?;
    let compose = doc
        .get("docker_compose_file")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("app-compose.json has no docker_compose_file"))?;
    Ok(ComposeReport {
        images: crate::compose::pinned_images(compose)?,
        settings: crate::compose::other_settings(&doc),
    })
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

/// Checks that need no network or quote, run first so a stale bundle or a
/// bad nonce is reported as such: the node's answer names the holder's
/// bundle, the nonce is fresh enough, and the node's binding is the one the
/// holder recomputes. Returns the binding digest the quote must carry.
pub fn check_local(
    info: &RecoveryInfo,
    bundle: &EscrowBundle,
    nonce: &str,
) -> Result<tinycloud_at_rest_escrow::Digest32> {
    bundle.validate()?;
    validate_nonce(nonce)?;
    ensure!(
        nonce.len() >= MIN_NONCE_LEN,
        "nonce must be at least {MIN_NONCE_LEN} chars; use `tinycloud-at-rest nonce`"
    );
    let efp = bundle.fingerprint();
    ensure!(
        info.efp == efp && info.ark_id == bundle.ark_id && info.generation == bundle.generation,
        "the node's escrow ({}) is not the bundle you hold ({efp}): your bundle is stale or for another node; get the current one",
        info.efp
    );
    // A reply made for another nonce is stale or replayed.
    let expected = recovery_binding(&info.recovery_recipient, &efp, nonce);
    ensure!(
        info.binding == expected,
        "the node's binding is not for your nonce: stale or replayed response; request a new one"
    );
    let digest = binding_digest(&expected);
    ensure!(
        info.binding_sha256 == digest,
        "binding_sha256 does not match binding"
    );
    Ok(digest)
}

/// Steps 2-5 on a DCAP-verified report. Returns the TCB line to show.
pub fn check_attestation(
    info: &RecoveryInfo,
    trust: &TrustPolicy,
    td: &AttestedTd,
    digest: &tinycloud_at_rest_escrow::Digest32,
) -> Result<String> {
    trust.validate()?;
    let tcb = check_tcb(td, trust)?;
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
    Ok(tcb)
}

/// [`check_local`] then [`check_attestation`].
#[cfg(test)]
fn check_recovery(
    info: &RecoveryInfo,
    bundle: &EscrowBundle,
    nonce: &str,
    trust: &TrustPolicy,
    td: &AttestedTd,
) -> Result<String> {
    let digest = check_local(info, bundle, nonce)?;
    check_attestation(info, trust, td, &digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tinycloud_at_rest_escrow::{
        Ark, ArkId, Digest32, HolderRecipient, RecipientPolicy, RecoveryIdentity,
    };

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
        EscrowBundle::create(
            &Ark::generate(),
            ArkId::generate(),
            1,
            &holders,
            RecipientPolicy::AllowSoftware,
        )
        .unwrap()
    }

    fn event(name: &str, payload: &str) -> serde_json::Value {
        serde_json::json!({
            "imr": 3, "event_type": RUNTIME_EVENT_TYPE, "digest": "",
            "event": name, "event_payload": payload,
        })
    }

    fn boot_events(app_id: &str, compose: &str) -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({"imr": 0, "event_type": 1, "digest": "00", "event": "", "event_payload": ""}),
            event("system-preparing", ""),
            event("app-id", app_id),
            event("compose-hash", compose),
            event("instance-id", "33"),
            event("boot-mr-done", ""),
            event("system-ready", ""),
        ]
    }

    fn event_log(app_id: &str, compose: &str) -> String {
        serde_json::Value::Array(boot_events(app_id, compose)).to_string()
    }

    fn rtmr3_of(log: &str) -> [u8; 48] {
        replay_rtmr3(&serde_json::from_str::<Vec<Event>>(log).unwrap()).unwrap()
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
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&digest.0);
        let td = AttestedTd {
            tcb_status: TcbStatus::UpToDate,
            advisory_ids: vec![],
            td_attributes: [0; 8],
            mr_td: [0xa0; 48],
            rtmr: [[0xa1; 48], [0xa2; 48], [0xa3; 48], rtmr3_of(&log)],
            report_data,
        };
        let trust = TrustPolicy {
            app_id: APP_ID.into(),
            compose_hash: COMPOSE.into(),
            mrtd: hex::encode([0xa0; 48]),
            rtmr0: hex::encode([0xa1; 48]),
            rtmr1: hex::encode([0xa2; 48]),
            rtmr2: hex::encode([0xa3; 48]),
            allowed_tcb_status: default_tcb(),
            allowed_advisories: vec![],
        };
        let info = RecoveryInfo {
            version: tinycloud_at_rest_escrow::RECOVERY_INFO_VERSION,
            mode: "dstack".into(),
            state: "unlocked".into(),
            ark_id: bundle.ark_id,
            generation: bundle.generation,
            efp: bundle.fingerprint(),
            canary_fp: bundle.canary_fp,
            recovery_recipient: tee.recipient(),
            binding: binding.clone(),
            binding_sha256: digest,
            quote: Some("00".into()),
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

    impl Scenario {
        /// Replace the event log and keep RTMR3 consistent with it, as a TEE
        /// that really measured those events would.
        fn with_events(mut self, events: Vec<serde_json::Value>) -> Self {
            let log = serde_json::Value::Array(events).to_string();
            self.td.rtmr[3] = rtmr3_of(&log);
            self.info.event_log = Some(log);
            self
        }

        /// Replace the event log with one that doesn't replay (RTMR3 unchanged).
        fn with_events_unchecked(mut self, events: Vec<serde_json::Value>) -> Self {
            self.info.event_log = Some(serde_json::Value::Array(events).to_string());
            self
        }
    }

    fn check(s: &Scenario, nonce: &str) -> Result<String> {
        check_recovery(&s.info, &s.bundle, nonce, &s.trust, &s.td)
    }

    fn assert_refused(s: &Scenario, nonce: &str, needle: &str) {
        let err = check(s, nonce).expect_err("must refuse").to_string();
        assert!(err.contains(needle), "{err:?} lacks {needle:?}");
    }

    #[test]
    fn consistent_attestation_passes() {
        let line = check(&scenario(), NONCE).unwrap();
        assert!(line.contains("UpToDate"), "{line}");
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
        let mut s = scenario();
        s.td.mr_td[0] ^= 1;
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
        let other = "9999999999999999999999999999999999999999";
        let s = scenario().with_events(boot_events(other, COMPOSE));
        assert_refused(&s, NONCE, "app-id");
        let s = scenario().with_events(boot_events(APP_ID, &"9".repeat(64)));
        assert_refused(&s, NONCE, "compose-hash");
    }

    #[test]
    fn identity_events_after_boot_or_duplicated_are_refused() {
        // A compose-hash (or app-id) measured after boot-mr-done is something
        // the app itself could have extended: refused even if it matches.
        for name in ["compose-hash", "app-id"] {
            let mut events = boot_events(APP_ID, COMPOSE);
            let at = events.iter().position(|e| e["event"] == name).unwrap();
            let moved = events.remove(at);
            events.push(moved);
            assert_refused(
                &scenario().with_events(events),
                NONCE,
                "before boot completion",
            );
        }
        // Duplicated identity events, even with equal payloads.
        for (name, payload) in [("app-id", APP_ID), ("compose-hash", COMPOSE)] {
            let mut events = boot_events(APP_ID, COMPOSE);
            events.insert(2, event(name, payload));
            assert_refused(&scenario().with_events(events), NONCE, "exactly one");
        }
        // Missing, duplicated or reordered boot markers.
        let mut events = boot_events(APP_ID, COMPOSE);
        events.retain(|e| e["event"] != "boot-mr-done");
        assert_refused(&scenario().with_events(events), NONCE, "boot markers");
        let mut events = boot_events(APP_ID, COMPOSE);
        events.push(event("boot-mr-done", ""));
        assert_refused(&scenario().with_events(events), NONCE, "boot markers");
        let mut events = boot_events(APP_ID, COMPOSE);
        let ready = events
            .iter()
            .position(|e| e["event"] == "system-ready")
            .unwrap();
        let ready = events.remove(ready);
        events.insert(1, ready);
        assert_refused(&scenario().with_events(events), NONCE, "ordering");
    }

    fn v2_event(name: &str, payload_hex: &str, preimage: Option<String>) -> serde_json::Value {
        let canonical = serde_json::json!({
            "name": name, "payload": payload_hex, "type": RUNTIME_EVENT_TYPE,
        })
        .to_string();
        serde_json::json!({
            "imr": 3, "event_type": RUNTIME_EVENT_TYPE, "digest": "", "version": 2,
            "event": name, "event_payload": payload_hex,
            "preimage": preimage.unwrap_or_else(|| hex::encode(canonical)),
        })
    }

    #[test]
    fn v2_events_replay_and_a_non_canonical_preimage_is_refused() {
        let mut events = boot_events(APP_ID, COMPOSE);
        events[3] = v2_event("compose-hash", COMPOSE, None);
        check(&scenario().with_events(events.clone()), NONCE).unwrap();

        // Same digest input, different bytes: a reordered-key preimage.
        let reordered = serde_json::json!({"type": RUNTIME_EVENT_TYPE, "name": "compose-hash", "payload": COMPOSE});
        events[3] = v2_event(
            "compose-hash",
            COMPOSE,
            Some(hex::encode(reordered.to_string())),
        );
        let log = serde_json::Value::Array(events.clone()).to_string();
        let err = replay_rtmr3(&serde_json::from_str::<Vec<Event>>(&log).unwrap()).unwrap_err();
        assert!(err.to_string().contains("not canonical"), "{err}");

        // A v2 event with no preimage, and an unknown version.
        let mut no_pre = v2_event("compose-hash", COMPOSE, None);
        no_pre.as_object_mut().unwrap().remove("preimage");
        events[3] = no_pre;
        let log = serde_json::Value::Array(events.clone()).to_string();
        assert!(replay_rtmr3(&serde_json::from_str::<Vec<Event>>(&log).unwrap()).is_err());
        events[3]["version"] = serde_json::json!(3);
        let log = serde_json::Value::Array(events).to_string();
        assert!(replay_rtmr3(&serde_json::from_str::<Vec<Event>>(&log).unwrap()).is_err());
    }

    #[test]
    fn debug_td_is_refused() {
        let mut s = scenario();
        s.td.td_attributes[0] |= 1;
        assert_refused(&s, NONCE, "debug TD");
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

    #[test]
    fn malformed_event_logs_are_refused() {
        let mut s = scenario();
        s.info.event_log = None;
        assert_refused(&s, NONCE, "no event log");
        let mut s = scenario();
        s.info.event_log = Some("{not json".into());
        assert_refused(&s, NONCE, "not a JSON array");
        let mut s = scenario();
        s.info.event_log = Some("[]".into());
        assert_refused(&s, NONCE, "no RTMR3 events");

        let mut events = boot_events(APP_ID, COMPOSE);
        events[1]["imr"] = 4.into();
        assert_refused(
            &scenario().with_events_unchecked(events),
            NONCE,
            "invalid IMR",
        );
        let mut events = boot_events(APP_ID, COMPOSE);
        events[2]["event_type"] = 1.into();
        assert_refused(
            &scenario().with_events_unchecked(events),
            NONCE,
            "unsupported type",
        );
        let mut events = boot_events(APP_ID, COMPOSE);
        events[2]["event_payload"] = "xyz".into();
        assert_refused(&scenario().with_events_unchecked(events), NONCE, "not hex");
    }

    #[test]
    fn binding_digest_must_match_the_binding() {
        let mut s = scenario();
        s.info.binding_sha256 = Digest32([3; 32]);
        assert_refused(&s, NONCE, "binding_sha256");
    }

    #[test]
    fn local_problems_are_named_before_any_network_or_quote_check() {
        // A quote that would fail every attestation check: the local cause wins.
        let mut s = scenario();
        s.td.tcb_status = TcbStatus::Revoked;
        s.td.mr_td = [0; 48];
        s.info.efp = Digest32([7; 32]);
        let err = check_local(&s.info, &s.bundle, NONCE)
            .unwrap_err()
            .to_string();
        assert!(err.contains("stale"), "{err}");
        let s = scenario();
        let err = check_local(&s.info, &s.bundle, "short")
            .unwrap_err()
            .to_string();
        assert!(err.contains("at least 22"), "{err}");
    }

    #[test]
    fn only_an_attested_tee_answer_is_considered() {
        let mut s = scenario();
        assert!(require_attested(&s.info).is_ok());
        s.info.mode = "classic".into();
        assert!(require_attested(&s.info)
            .unwrap_err()
            .to_string()
            .contains("not in a TEE"));
        let mut s = scenario();
        s.info.quote = None;
        assert!(require_attested(&s.info)
            .unwrap_err()
            .to_string()
            .contains("no TDX quote"));
        s.info.quote = Some("zz".into());
        assert!(require_attested(&s.info).is_err());
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
        s.trust.allowed_tcb_status = vec![
            AcceptedTcb::UpToDate,
            AcceptedTcb::SWHardeningNeeded,
            AcceptedTcb::ConfigurationNeeded,
            AcceptedTcb::ConfigurationAndSWHardeningNeeded,
        ];
        s.trust.allowed_advisories = td.advisory_ids.clone();
        let log_rtmr3 = s.td.rtmr[3];
        s.td = td;
        s.td.rtmr[3] = log_rtmr3;
        assert_refused(&s, NONCE, "REPORTDATA does not bind");
    }

    /// The genuine fixture quote and collateral, with every TCB level of the
    /// (otherwise genuine) TCB info forced to `status` and `advisories`.
    fn real_quote_with_status(status: TcbStatus, advisories: &[&str]) -> Result<AttestedTd> {
        let advisories: Vec<String> = advisories.iter().map(|s| s.to_string()).collect();
        let verified = dcap_qvl::verify::QuoteVerifier::new_prod()
            .dangerous_verify_with_tcb_override(
                TDX_QUOTE,
                &collateral(TDX_COLLATERAL),
                FIXTURE_NOW,
                |mut info| {
                    for level in &mut info.tcb_levels {
                        level.tcb_status = status;
                        level.advisory_ids = advisories.clone();
                    }
                    info
                },
            )
            .map_err(|e| anyhow!("DCAP: {e}"))?;
        AttestedTd::from_report(&verified)
    }

    #[test]
    fn every_tcb_class_from_a_real_quote() {
        const SA: &str = "INTEL-SA-00837";
        let default = scenario().trust;
        let mut lenient = default.clone();
        lenient.allowed_tcb_status = vec![
            AcceptedTcb::UpToDate,
            AcceptedTcb::SWHardeningNeeded,
            AcceptedTcb::ConfigurationNeeded,
            AcceptedTcb::ConfigurationAndSWHardeningNeeded,
        ];
        let mut pinned = lenient.clone();
        pinned.allowed_advisories = vec![SA.into()];

        let up = real_quote_with_status(TcbStatus::UpToDate, &[]).unwrap();
        assert_eq!(up.tcb_status, TcbStatus::UpToDate);
        check_tcb(&up, &default).unwrap();

        for status in [
            TcbStatus::SWHardeningNeeded,
            TcbStatus::ConfigurationNeeded,
            TcbStatus::ConfigurationAndSWHardeningNeeded,
        ] {
            let td = real_quote_with_status(status, &[SA]).unwrap();
            assert_eq!(td.tcb_status, status);
            let err = check_tcb(&td, &default).unwrap_err().to_string();
            assert!(err.contains("not one of"), "{status}: {err}");
            let err = check_tcb(&td, &lenient).unwrap_err().to_string();
            assert!(err.contains("does not pin"), "{status}: {err}");
            let ok = check_tcb(&td, &pinned).unwrap();
            assert!(ok.contains(SA), "{ok}");
        }

        // A hardening class with no advisories at all is anomalous: refused.
        let bare = real_quote_with_status(TcbStatus::SWHardeningNeeded, &[]).unwrap();
        let err = check_tcb(&bare, &pinned).unwrap_err().to_string();
        assert!(err.contains("anomalous"), "{err}");

        // Never accepted, whatever the policy says.
        for status in [
            TcbStatus::OutOfDate,
            TcbStatus::OutOfDateConfigurationNeeded,
            TcbStatus::TDRelaunchAdvised,
            TcbStatus::TDRelaunchAdvisedConfigurationNeeded,
            TcbStatus::Revoked,
        ] {
            match real_quote_with_status(status, &[SA]) {
                // DCAP itself rejects some classes (e.g. Revoked).
                Err(e) => assert!(e.to_string().contains("DCAP"), "{status}: {e}"),
                Ok(td) => {
                    let err = check_tcb(&td, &pinned).unwrap_err().to_string();
                    assert!(err.contains("never accepted"), "{status}: {err}");
                }
            }
        }

        // An unknown status string from the verifier is refused.
        let mut report = dcap_qvl::verify::QuoteVerifier::new_prod()
            .dangerous_verify_with_tcb_override(
                TDX_QUOTE,
                &collateral(TDX_COLLATERAL),
                FIXTURE_NOW,
                |info| info,
            )
            .unwrap();
        report.status = "MostlyFine".into();
        assert!(AttestedTd::from_report(&report)
            .unwrap_err()
            .to_string()
            .contains("unknown TCB status"));
    }

    #[test]
    fn trust_policy_cannot_name_refused_classes() {
        let base = r#""app_id":"1111111111111111111111111111111111111111","compose_hash":"22","mrtd":"a","rtmr0":"a","rtmr1":"a","rtmr2":"a""#;
        for status in ["OutOfDate", "Revoked", "TDRelaunchAdvised", "NotAStatus"] {
            let json = format!(r#"{{{base},"allowed_tcb_status":["{status}"]}}"#);
            assert!(
                serde_json::from_str::<TrustPolicy>(&json).is_err(),
                "{status}"
            );
        }
        let json = format!(r#"{{{base},"allowed_tcb_status":["SWHardeningNeeded"]}}"#);
        assert!(serde_json::from_str::<TrustPolicy>(&json).is_ok());
        let mut t = scenario().trust;
        t.allowed_advisories = vec!["CVE-2024-1".into()];
        assert!(t.validate().is_err());
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
    fn platform_missing_from_the_tcb_info_is_refused() {
        // A real quote whose platform TCB level the collateral doesn't list.
        let err = verify_quote(
            TDX_QUOTE_OUTDATED,
            &collateral(TDX_COLLATERAL_OUTDATED),
            FIXTURE_NOW_OUTDATED,
        )
        .expect_err("unlisted platform must be refused");
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

    fn app_compose(compose_yaml: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "manifest_version": 2,
            "name": "tinycloud",
            "runner": "docker-compose",
            "docker_compose_file": compose_yaml,
        }))
        .unwrap()
    }

    #[test]
    fn app_compose_must_match_the_pin_and_reference_images_by_digest() {
        let digest = "a".repeat(64);
        let good = app_compose(&format!(
            "services:\n  node:\n    image: ghcr.io/tinycloudlabs/tinycloud-node@sha256:{digest}\n  ingress:\n    image: \"caddy@sha256:{digest}\"\n"
        ));
        let mut trust = scenario().trust;
        trust.compose_hash = hex::encode(Sha256::digest(&good));
        assert_eq!(check_app_compose(&good, &trust).unwrap().images.len(), 2);

        let tagged = app_compose(&format!(
            "services:\n  node:\n    image: ghcr.io/tinycloudlabs/tinycloud-node@sha256:{digest}\n  shipper:\n    image: vector:0.40\n"
        ));
        trust.compose_hash = hex::encode(Sha256::digest(&tagged));
        let err = check_app_compose(&tagged, &trust).unwrap_err().to_string();
        assert!(err.contains("vector:0.40"), "{err}");

        trust.compose_hash = "0".repeat(64);
        let err = check_app_compose(&good, &trust).unwrap_err().to_string();
        assert!(err.contains("trust policy pins compose_hash"), "{err}");
    }
}
