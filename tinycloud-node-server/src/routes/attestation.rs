use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;

use crate::routes::public::{ClientIp, RateLimiter};
use crate::tee::{AttestationResponse, TeeContext};

/// Longest accepted `nonce`, in bytes.
const MAX_NONCE_LEN: usize = 64;

/// Get attestation information about this server instance.
///
/// In TEE mode (dstack), returns a TDX quote that can be verified
/// against dstack-verifier to cryptographically prove:
/// - The server runs on genuine Intel TDX hardware
/// - The exact Docker image and config match the published compose hash
/// - Keys are derived deterministically in hardware
///
/// In classic mode, returns a simple response indicating no TEE is available.
///
/// An optional `nonce` (1-64 characters of `A-Z a-z 0-9 - _`) binds the quote
/// to the caller's challenge; without one the quote proves no freshness. The
/// quote's REPORTDATA carries SHA-256 of the returned `key_binding`, which
/// includes the enforcer DID and the nonce (see `docs/attestation.md`).
/// Before answering 200 the node checks that the quote's REPORTDATA field
/// holds that digest; it does not verify the quote's signature.
///
/// Shares the per-IP limit of the public routes, since each call quotes.
/// Returns 400 for a malformed nonce and 503 if the TEE cannot produce a
/// quote bound to the digest.
#[get("/attestation?<nonce>")]
pub async fn attestation(
    tee: &State<Option<TeeContext>>,
    client_ip: ClientIp,
    rate_limiter: &State<RateLimiter>,
    nonce: Option<String>,
) -> Result<Json<AttestationResponse>, (Status, String)> {
    rate_limiter
        .check(client_ip.0)
        .map_err(|s| (s, "Rate limit exceeded".to_string()))?;
    if let Some(nonce) = nonce.as_deref() {
        let well_formed = (1..=MAX_NONCE_LEN).contains(&nonce.len())
            && nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !well_formed {
            return Err((
                Status::BadRequest,
                format!("nonce must be 1-{MAX_NONCE_LEN} characters of A-Z, a-z, 0-9, '-' or '_'"),
            ));
        }
    }
    match tee.inner() {
        Some(ctx) => {
            // In TEE mode, get a fresh quote from dstack
            #[cfg(feature = "dstack")]
            {
                dstack_attestation(&crate::dstack::socket_path(), ctx, nonce.as_deref()).await
            }
            #[cfg(not(feature = "dstack"))]
            {
                let _ = nonce; // suppress unused warning
                let _ = ctx;
                Ok(Json(AttestationResponse::Classic {
                    message: "TEE context available but dstack feature not compiled in".to_string(),
                }))
            }
        }
        None => Ok(Json(AttestationResponse::Classic {
            message: "This instance is not running in a TEE".to_string(),
        })),
    }
}

/// Quote this instance's key binding through the dstack guest agent at
/// `socket`. Any failure is a 503; the cause stays in the operator log.
#[cfg(any(test, feature = "dstack"))]
async fn dstack_attestation(
    socket: &str,
    ctx: &TeeContext,
    nonce: Option<&str>,
) -> Result<Json<AttestationResponse>, (Status, String)> {
    use sha2::Digest as _;

    let key_binding = format!(
        "xyz.tinycloud.share/tee-key/v1\\0:{}:{}",
        ctx.enforcer_did,
        nonce.unwrap_or("")
    );
    // REPORTDATA holds 64 bytes, so the quote carries the binding's SHA-256
    // and the response returns the preimage for verifiers to recompute.
    let report_data = sha2::Sha256::digest(key_binding.as_bytes());

    let quote_resp = crate::dstack::get_quote(socket, &report_data)
        .await
        .map_err(|e| {
            // `{e}` is only the outermost context, a fixed message from this
            // code; the full chain may quote agent output, so it is debug-only.
            tracing::error!(error_class = %e, "TDX quote unavailable");
            tracing::debug!("TDX quote failure: {e:#}");
            (
                Status::ServiceUnavailable,
                "quote generation failed".to_string(),
            )
        })?;
    Ok(Json(AttestationResponse::Dstack {
        quote: quote_resp.quote,
        event_log: quote_resp.event_log,
        compose_hash: ctx.compose_hash.clone(),
        app_id: ctx.app_id.clone(),
        enforcer_did: ctx.enforcer_did.clone(),
        key_binding,
        key_binding_sha256: hex::encode(report_data),
        timestamp: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dstack::stub;
    use sha2::Digest;

    // A real node did:key; with the domain tag alone the raw binding is
    // already past dstack's 64-byte REPORTDATA limit.
    const DID: &str = "did:key:z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK";

    fn ctx() -> TeeContext {
        TeeContext {
            app_id: "app".into(),
            compose_hash: "compose".into(),
            instance_id: "instance".into(),
            enforcer_did: DID.into(),
        }
    }

    /// The response and the report_data the guest agent was asked to quote.
    async fn attest(nonce: Option<&str>) -> (AttestationResponse, Vec<u8>) {
        let agent = stub::serve_quote();
        let response = dstack_attestation(&agent.socket, &ctx(), nonce)
            .await
            .unwrap()
            .into_inner();
        let sent = stub::requested_report_data(&agent.request.await.unwrap());
        (response, sent)
    }

    #[tokio::test]
    async fn guest_agent_error_is_a_503_not_a_classic_response() {
        let agent = stub::serve_once("400 Bad Request", r#"{"error":"Report data is too long"}"#);
        let failure = dstack_attestation(&agent.socket, &ctx(), Some("n"))
            .await
            .unwrap_err();
        assert_eq!(
            failure,
            (
                Status::ServiceUnavailable,
                "quote generation failed".to_string()
            )
        );
    }

    #[tokio::test]
    async fn quote_with_other_reportdata_is_a_503_even_when_the_echo_matches() {
        let agent = stub::serve_quote_with(|_| hex::encode(stub::tdx_quote(&[0x24; 64])));
        let failure = dstack_attestation(&agent.socket, &ctx(), Some("n"))
            .await
            .unwrap_err();
        assert_eq!(failure.0, Status::ServiceUnavailable);
    }

    #[tokio::test]
    async fn truncated_quote_is_a_503() {
        let agent = stub::serve_quote_with(|padded| hex::encode(&stub::tdx_quote(padded)[..600]));
        let failure = dstack_attestation(&agent.socket, &ctx(), Some("n"))
            .await
            .unwrap_err();
        assert_eq!(failure.0, Status::ServiceUnavailable);
    }

    #[tokio::test]
    async fn quote_request_carries_a_32_byte_binding_hash() {
        let (_, sent) = attest(Some("a-verifier-chosen-nonce-of-some-length")).await;
        assert_eq!(sent.len(), 32);
    }

    #[tokio::test]
    async fn each_nonce_is_bound_into_distinct_report_data() {
        let (response, with_a) = attest(Some("nonce-a")).await;
        let (_, with_b) = attest(Some("nonce-b")).await;
        let (_, without) = attest(None).await;
        assert_ne!(with_a, with_b);
        assert_ne!(with_a, without);
        let AttestationResponse::Dstack { key_binding, .. } = response else {
            panic!("expected a dstack attestation");
        };
        assert!(key_binding.ends_with(":nonce-a"), "{key_binding}");
    }

    #[tokio::test]
    async fn verifier_recomputes_report_data_from_the_returned_preimage() {
        let nonce = "verifier-nonce-1";
        let (response, _) = attest(Some(nonce)).await;
        let AttestationResponse::Dstack {
            quote,
            enforcer_did,
            key_binding,
            key_binding_sha256,
            ..
        } = response
        else {
            panic!("expected a dstack attestation");
        };
        // A verifier rebuilds the preimage from the DID it expects and its own nonce.
        assert_eq!(enforcer_did, DID);
        assert_eq!(
            key_binding,
            format!("xyz.tinycloud.share/tee-key/v1\\0:{DID}:{nonce}")
        );
        let digest = sha2::Sha256::digest(key_binding.as_bytes());
        assert_eq!(key_binding_sha256, hex::encode(digest));
        // Read REPORTDATA from the returned quote (TDX v4: header 48 bytes,
        // REPORTDATA at TD report body offset 520): digest, then 32 zeros.
        let quote = hex::decode(quote).unwrap();
        let report_data = &quote[48 + 520..48 + 584];
        assert_eq!(&report_data[..32], &digest[..]);
        assert_eq!(&report_data[32..], &[0u8; 32]);
    }

    /// A node with no TEE behind a limiter allowing `burst` requests per IP.
    async fn client(burst: u32) -> rocket::local::asynchronous::Client {
        let limits = crate::config::PublicSpacesConfig {
            rate_limit_per_minute: 0,
            rate_limit_burst: burst,
            ..Default::default()
        };
        let rocket = rocket::build()
            .manage(None::<TeeContext>)
            .manage(crate::routes::public::RateLimiter::new(&limits))
            .mount("/", rocket::routes![attestation]);
        rocket::local::asynchronous::Client::untracked(rocket)
            .await
            .unwrap()
    }

    /// GET `uri` from client address `ip`; the limiter keys on it.
    async fn status_from(
        client: &rocket::local::asynchronous::Client,
        ip: &str,
        uri: &str,
    ) -> Status {
        let remote = format!("{ip}:4000").parse().unwrap();
        client
            .get(uri.to_owned())
            .remote(remote)
            .dispatch()
            .await
            .status()
    }

    #[tokio::test]
    async fn nonce_must_be_1_to_64_url_safe_characters() {
        let client = client(10).await;
        let longest = "n".repeat(64);
        let too_long = "n".repeat(65);
        for (nonce, status) in [
            ("abc-DEF_123", Status::Ok),
            (longest.as_str(), Status::Ok),
            (too_long.as_str(), Status::BadRequest),
            ("a:b", Status::BadRequest),
            ("", Status::BadRequest),
        ] {
            let got =
                status_from(&client, "192.0.2.1", &format!("/attestation?nonce={nonce}")).await;
            assert_eq!(got, status, "nonce {nonce:?}");
        }
    }

    #[tokio::test]
    async fn attestation_is_rate_limited_per_client() {
        let client = client(1).await;
        assert_eq!(
            status_from(&client, "192.0.2.1", "/attestation").await,
            Status::Ok
        );
        assert_eq!(
            status_from(&client, "192.0.2.1", "/attestation").await,
            Status::TooManyRequests
        );
        assert_eq!(
            status_from(&client, "192.0.2.2", "/attestation").await,
            Status::Ok
        );
    }
}
