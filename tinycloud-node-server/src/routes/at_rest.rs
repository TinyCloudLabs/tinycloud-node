//! Escrow ceremony and recovery endpoints (TC-887 S1). All public data; see
//! `docs/at-rest-escrow.md` and `tinycloud-at-rest` for the holder side.
//!
//! - `GET /at-rest/status`: mode, key state, escrow fingerprint, gate.
//! - `GET /at-rest/escrow`: the escrow bundle holders decrypt from.
//! - `GET /at-rest/escrow/record`: the ceremony verification record, only if
//!   its MAC verifies under the live key.
//! - `GET /at-rest/recovery?nonce=`: this boot's recovery recipient, bound
//!   with the holder's nonce and the EFP into a TDX quote.
//! - `POST /at-rest/recovery/shares`: one share sealed to that recipient.
//!
//! Share bodies are capped at 4 KiB and rate limited per IP. Shares that
//! don't authenticate (don't decrypt, or match no commitment) are limited
//! per client and never spend the node's per-boot share budget, which only
//! genuine shares count against. Neither share bytes nor ciphertexts are
//! logged.

use rocket::data::{Data, ToByteUnit};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;
use serde::Serialize;
use tinycloud_at_rest_escrow::{
    binding_digest, recovery_binding, validate_nonce, EscrowBundle, RecoveryInfo,
    VerificationRecord, MAX_WRAPPED_SHARE, RECOVERY_INFO_VERSION,
};
use tinycloud_core::at_rest::keyring::{
    AtRestError, EscrowView, KeyringState, ShareOutcome, ShareRefusal,
};

use crate::at_rest::{AtRestRuntime, AtRestState};
use crate::routes::public::{ClientIp, RateLimiter};
use crate::tee::TeeContext;

type Refusal = (Status, String);

fn not_enabled() -> Refusal {
    (
        Status::NotFound,
        "at-rest keys are not enabled on this node".into(),
    )
}

/// A keyring error as an answer: 503 when a retry may help (store or mirror
/// unreachable, locked, a concurrent change), 500 when an operator must act.
/// The body is a stable, non-secret reason; backend detail goes to the log.
fn internal(e: AtRestError) -> Refusal {
    ::tracing::error!(error = %e, "at-rest keyring error");
    let status = if e.is_transient() {
        Status::ServiceUnavailable
    } else {
        Status::InternalServerError
    };
    (status, format!("at-rest keyring error: {}", e.reason()))
}

async fn view(runtime: &AtRestRuntime) -> Result<EscrowView, Refusal> {
    let keyring = runtime.keyring().ok_or_else(not_enabled)?;
    keyring.escrow_view().await.map_err(internal)?.ok_or((
        Status::NotFound,
        "no escrow bundle is available (no recipients configured, or a locked node without a pinned at_rest.escrow.verified_fp)".into(),
    ))
}

#[derive(Serialize)]
pub struct AtRestStatus {
    mode: &'static str,
    state: &'static str,
    encrypting: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    efp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<u32>,
    verified: bool,
}

#[get("/at-rest/status")]
pub async fn at_rest_status(at_rest: AtRestState<'_>) -> Result<Json<AtRestStatus>, Refusal> {
    let runtime = at_rest.0.ok_or_else(not_enabled)?;
    let escrow = match runtime.keyring() {
        Some(k) => k.escrow_view().await.map_err(internal)?,
        None => None,
    };
    Ok(Json(AtRestStatus {
        mode: runtime.mode_name(),
        state: runtime.state_name(),
        encrypting: runtime.encrypting(),
        efp: escrow.as_ref().map(|v| v.efp.to_string()),
        generation: escrow.as_ref().map(|v| v.generation),
        verified: escrow.is_some_and(|v| v.verified),
    }))
}

#[get("/at-rest/escrow")]
pub async fn at_rest_escrow(at_rest: AtRestState<'_>) -> Result<Json<EscrowBundle>, Refusal> {
    let runtime = at_rest.0.ok_or_else(not_enabled)?;
    Ok(Json(view(runtime).await?.bundle))
}

#[get("/at-rest/escrow/record")]
pub async fn at_rest_escrow_record(
    at_rest: AtRestState<'_>,
) -> Result<Json<VerificationRecord>, Refusal> {
    let runtime = at_rest.0.ok_or_else(not_enabled)?;
    let keyring = runtime.keyring().ok_or_else(not_enabled)?;
    keyring
        .verification_record()
        .await
        .map_err(internal)?
        .map(Json)
        .ok_or((
            Status::NotFound,
            "no verified ceremony record for the active escrow".into(),
        ))
}

#[get("/at-rest/recovery?<nonce>")]
pub async fn at_rest_recovery(
    at_rest: AtRestState<'_>,
    tee: &State<Option<TeeContext>>,
    client_ip: ClientIp,
    rate_limiter: &State<RateLimiter>,
    nonce: String,
) -> Result<Json<RecoveryInfo>, Refusal> {
    rate_limiter
        .check(client_ip.0)
        .map_err(|s| (s, "Rate limit exceeded".to_string()))?;
    validate_nonce(&nonce).map_err(|e| (Status::BadRequest, e.to_string()))?;
    let runtime = at_rest.0.ok_or_else(not_enabled)?;
    let view = view(runtime).await?;
    let binding = recovery_binding(&view.recovery_recipient, &view.efp, &nonce);
    let digest = binding_digest(&binding);
    let (mode, quote, event_log) = quote_binding(tee.inner().as_ref(), &digest.0).await?;
    Ok(Json(RecoveryInfo {
        version: RECOVERY_INFO_VERSION,
        mode: mode.into(),
        state: match view.state {
            KeyringState::Locked => "locked",
            _ => "unlocked",
        }
        .into(),
        ark_id: view.ark_id,
        generation: view.generation,
        efp: view.efp,
        canary_fp: view.canary_fp,
        recovery_recipient: view.recovery_recipient,
        binding,
        binding_sha256: digest,
        quote,
        event_log,
        shares_held: view.shares_held,
    }))
}

/// A TDX quote over `digest`, or `classic` with no quote outside a TEE (a
/// holder's tool refuses to release a share then).
async fn quote_binding(
    tee: Option<&TeeContext>,
    digest: &[u8; 32],
) -> Result<(&'static str, Option<String>, Option<String>), Refusal> {
    match tee {
        #[cfg(feature = "dstack")]
        Some(_) => {
            let quote = crate::dstack::get_quote(&crate::dstack::socket_path(), digest)
                .await
                .map_err(|e| {
                    ::tracing::error!(error_class = %e, "TDX quote unavailable for at-rest recovery");
                    (
                        Status::ServiceUnavailable,
                        "quote generation failed".to_string(),
                    )
                })?;
            Ok(("dstack", Some(quote.quote), Some(quote.event_log)))
        }
        _ => {
            let _ = digest;
            Ok(("classic", None, None))
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ShareAnswer {
    outcome: &'static str,
    shares_held: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    efp: Option<String>,
    /// After a recovery: whether encryption is enabled again (the gate
    /// passed), or why not.
    #[serde(skip_serializing_if = "Option::is_none")]
    gate: Option<String>,
}

#[post("/at-rest/recovery/shares", data = "<body>")]
pub async fn at_rest_recovery_share(
    at_rest: AtRestState<'_>,
    // TC-1357: ClientIp trusts the proxy IP header from any peer; per-client
    // limits are best effort until it is trusted only from the ingress.
    client_ip: ClientIp,
    rate_limiter: &State<RateLimiter>,
    body: Data<'_>,
) -> Result<Json<ShareAnswer>, Refusal> {
    rate_limiter
        .check(client_ip.0)
        .map_err(|s| (s, "Rate limit exceeded".to_string()))?;
    let runtime = at_rest.0.ok_or_else(not_enabled)?;
    let keyring = runtime.keyring().ok_or_else(not_enabled)?;
    let failures = runtime.share_failures();
    if !failures.allows(client_ip.0) {
        return Err((
            Status::TooManyRequests,
            "too many rejected shares from this client; retry later".into(),
        ));
    }
    let wrapped = body
        .open(MAX_WRAPPED_SHARE.bytes())
        .into_bytes()
        .await
        .map_err(|_| {
            failures.record_failure(client_ip.0);
            (Status::BadRequest, "could not read the share".to_string())
        })?;
    if !wrapped.is_complete() {
        failures.record_failure(client_ip.0);
        return Err((
            Status::PayloadTooLarge,
            format!("a wrapped share is at most {MAX_WRAPPED_SHARE} bytes"),
        ));
    }
    match keyring.submit_share(&wrapped).await {
        Ok(ShareOutcome::Held { shares_held }) => Ok(Json(ShareAnswer {
            outcome: "held",
            shares_held,
            efp: None,
            gate: None,
        })),
        Ok(ShareOutcome::Verified { efp }) => {
            let gate = runtime.reevaluate().await;
            Ok(Json(ShareAnswer {
                outcome: "verified",
                shares_held: vec![],
                efp: Some(efp.to_string()),
                gate: Some(match gate {
                    Ok(_) => "open".into(),
                    Err(r) => r.to_string(),
                }),
            }))
        }
        Ok(ShareOutcome::Unlocked) => {
            let gate = match runtime.reevaluate().await {
                Ok(_) => "open".to_string(),
                Err(r) => {
                    ::tracing::error!(reason = %r, "at-rest keys recovered, but encryption stays off");
                    r.to_string()
                }
            };
            Ok(Json(ShareAnswer {
                outcome: "unlocked",
                shares_held: vec![],
                efp: None,
                gate: Some(gate),
            }))
        }
        Err(ShareRefusal::RateLimited) => Err((
            Status::TooManyRequests,
            "too many share submissions this boot; retry later".into(),
        )),
        Err(ShareRefusal::NoBundle(why)) => Err((Status::Conflict, why.into())),
        Err(ShareRefusal::Invalid(e)) => {
            failures.record_failure(client_ip.0);
            Err((Status::BadRequest, format!("share rejected: {e}")))
        }
        Err(ShareRefusal::Keyring(e)) => Err(internal(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_errors_answer_with_a_status_and_a_non_secret_reason() {
        let (status, body) = internal(AtRestError::Mirror(
            "s3://bucket/secret-path: access denied".into(),
        ));
        assert_eq!(status, Status::ServiceUnavailable);
        assert_eq!(body, "at-rest keyring error: mirror_unavailable");
        let (status, body) = internal(AtRestError::Inconsistent(
            "an older ARK generation's chain is missing or does not open",
        ));
        assert_eq!(status, Status::InternalServerError);
        assert!(
            body.contains("inconsistent: an older ARK generation"),
            "{body}"
        );
        let (status, body) = internal(AtRestError::EscrowHoldersChanged);
        assert_eq!(
            (status, body.as_str()),
            (
                Status::InternalServerError,
                "at-rest keyring error: escrow_holders_changed"
            )
        );
    }
}
