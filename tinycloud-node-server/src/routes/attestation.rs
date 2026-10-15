use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;

use crate::tee::{AttestationResponse, TeeContext};

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
/// An optional `nonce` parameter can be included to prevent replay attacks.
/// The quote's REPORTDATA carries SHA-256 of the returned `key_binding`, which
/// includes the enforcer DID and the nonce (see `docs/attestation.md`).
///
/// Returns 503 if the TEE cannot produce a quote.
#[get("/attestation?<nonce>")]
pub async fn attestation(
    tee: &State<Option<TeeContext>>,
    nonce: Option<String>,
) -> Result<Json<AttestationResponse>, (Status, String)> {
    match tee.inner() {
        Some(ctx) => {
            // In TEE mode, get a fresh quote from dstack
            #[cfg(feature = "dstack")]
            {
                let socket = crate::dstack::socket_path();
                dstack_attestation(&socket, ctx, nonce.as_deref())
                    .await
                    .map(Json)
                    .map_err(|e| {
                        tracing::error!("Failed to get TDX quote: {:#}", e);
                        (
                            Status::ServiceUnavailable,
                            format!("quote generation failed: {e:#}"),
                        )
                    })
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

/// Quote this instance's key binding through the dstack guest agent at `socket`.
#[cfg(any(test, feature = "dstack"))]
async fn dstack_attestation(
    socket: &str,
    ctx: &TeeContext,
    nonce: Option<&str>,
) -> anyhow::Result<AttestationResponse> {
    use sha2::Digest as _;

    let key_binding = format!(
        "xyz.tinycloud.share/tee-key/v1\\0:{}:{}",
        ctx.enforcer_did,
        nonce.unwrap_or("")
    );
    // REPORTDATA holds 64 bytes, so the quote carries the binding's SHA-256
    // and the response returns the preimage for verifiers to recompute.
    let report_data = sha2::Sha256::digest(key_binding.as_bytes());

    let quote_resp = crate::dstack::get_quote(socket, &report_data).await?;
    Ok(AttestationResponse::Dstack {
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
    })
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
            .unwrap();
        let sent = stub::requested_report_data(&agent.request.await.unwrap());
        (response, sent)
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
        let (response, sent) = attest(Some(nonce)).await;
        let AttestationResponse::Dstack {
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
        // dstack zero-pads report_data into the quote's 64-byte REPORTDATA.
        let mut report_data = sent;
        report_data.resize(crate::dstack::MAX_REPORT_DATA_BYTES, 0);
        assert_eq!(&report_data[..32], &digest[..]);
        assert_eq!(&report_data[32..], &[0u8; 32]);
    }
}
