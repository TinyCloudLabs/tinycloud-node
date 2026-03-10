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
#[get("/attestation?<nonce>")]
pub async fn attestation(
    tee: &State<Option<TeeContext>>,
    nonce: Option<String>,
) -> Json<AttestationResponse> {
    match tee.inner() {
        Some(ctx) => {
            // In TEE mode, get a fresh quote from dstack
            #[cfg(feature = "dstack")]
            {
                let report_data = nonce.as_deref().unwrap_or("").as_bytes().to_vec();

                match crate::dstack::get_quote(&report_data).await {
                    Ok(quote_resp) => Json(AttestationResponse::Dstack {
                        quote: quote_resp.quote,
                        event_log: quote_resp.event_log,
                        compose_hash: ctx.compose_hash.clone(),
                        app_id: ctx.app_id.clone(),
                        timestamp: time::OffsetDateTime::now_utc()
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default(),
                    }),
                    Err(e) => {
                        tracing::error!("Failed to get TDX quote: {}", e);
                        Json(AttestationResponse::Classic {
                            message: format!(
                                "TEE context available but quote generation failed: {}",
                                e
                            ),
                        })
                    }
                }
            }
            #[cfg(not(feature = "dstack"))]
            {
                let _ = nonce; // suppress unused warning
                let _ = ctx;
                Json(AttestationResponse::Classic {
                    message: "TEE context available but dstack feature not compiled in".to_string(),
                })
            }
        }
        None => Json(AttestationResponse::Classic {
            message: "This instance is not running in a TEE".to_string(),
        }),
    }
}
