//! HTTP client for the tinycloud.link name+cert service.
//!
//! Endpoints (see `tinycloud-link/src/server.ts`):
//!   - PUT    /v1/names/:name    claim/update
//!   - DELETE /v1/names/:name    delete
//!   - POST   /v1/certs/:name    issue cert
//!
//! 409 responses are disambiguated by parsing the service's JSON error body
//! (`{"error": "..."}`, see `names.ts`/`server.ts`) rather than treated as a
//! single generic conflict: a 409 means either "name already claimed by a
//! different subject" (`NameConflict`) or "stale record sequence"
//! (`StaleSequence`) — the two have very different remediations, so callers
//! need to be able to tell them apart. 429 rate-limited responses are
//! likewise surfaced as their own variant.
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::Deserialize;
use std::time::Duration;

use super::payload::{CertRequestBody, NameClaimBody, NameDeleteBody};
use super::LinkError;

/// Response body for a successful cert issuance (`POST /v1/certs/:name`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertIssuanceResponse {
    pub cert_chain_pem: String,
    pub not_after: String,
}

pub struct LinkClient {
    http: Client,
    base_url: String,
}

impl LinkClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self, LinkError> {
        let http = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|err| LinkError::Http(err.to_string()))?;
        Ok(Self {
            http,
            base_url: base_url.into(),
        })
    }

    fn url(&self, path: &str) -> String {
        let base = self.base_url.trim_end_matches('/');
        format!("{base}{path}")
    }

    pub fn health(&self) -> Result<(), LinkError> {
        let response = self
            .http
            .get(self.url("/health"))
            .send()
            .map_err(|err| LinkError::Http(err.to_string()))?;
        if !response.status().is_success() {
            return Err(LinkError::UnexpectedStatus {
                status: response.status().as_u16(),
                body: response.text().unwrap_or_default(),
            });
        }
        Ok(())
    }

    pub fn put_name_claim(&self, body: &NameClaimBody) -> Result<(), LinkError> {
        let response = self
            .http
            .put(self.url(&format!(
                "/v1/names/{}",
                percent_encoding::utf8_percent_encode(
                    &body.name,
                    percent_encoding::NON_ALPHANUMERIC,
                )
            )))
            .json(body)
            .send()
            .map_err(|err| LinkError::Http(err.to_string()))?;
        interpret_response(response, &body.name)
    }

    pub fn delete_name(&self, body: &NameDeleteBody) -> Result<(), LinkError> {
        let response = self
            .http
            .delete(self.url(&format!(
                "/v1/names/{}",
                percent_encoding::utf8_percent_encode(
                    &body.name,
                    percent_encoding::NON_ALPHANUMERIC,
                )
            )))
            .json(body)
            .send()
            .map_err(|err| LinkError::Http(err.to_string()))?;
        interpret_response(response, &body.name)
    }

    pub fn post_cert_request(
        &self,
        body: &CertRequestBody,
    ) -> Result<CertIssuanceResponse, LinkError> {
        let response = self
            .http
            .post(self.url(&format!(
                "/v1/certs/{}",
                percent_encoding::utf8_percent_encode(
                    &body.name,
                    percent_encoding::NON_ALPHANUMERIC,
                )
            )))
            .json(body)
            .send()
            .map_err(|err| LinkError::Http(err.to_string()))?;

        let status = response.status();
        if status.is_success() {
            return response
                .json::<CertIssuanceResponse>()
                .map_err(|err| LinkError::Http(err.to_string()));
        }
        Err(map_error_status(status, response, &body.name))
    }
}

fn interpret_response(response: reqwest::blocking::Response, name: &str) -> Result<(), LinkError> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    Err(map_error_status(status, response, name))
}

fn map_error_status(
    status: StatusCode,
    response: reqwest::blocking::Response,
    name: &str,
) -> LinkError {
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body = response.text().unwrap_or_default();

    match status {
        StatusCode::CONFLICT => classify_conflict(name, body),
        StatusCode::TOO_MANY_REQUESTS => LinkError::RateLimited { retry_after, body },
        _ => LinkError::UnexpectedStatus {
            status: status.as_u16(),
            body,
        },
    }
}

/// Error body shape used by every `NameError`/stale-sequence response in
/// `server.ts`: `{"error": "<message>"}`.
#[derive(Debug, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    error: String,
}

/// Disambiguate a 409 by its error message. The service only ever returns
/// two distinct 409 causes on the endpoints this client calls: "name already
/// claimed by a different subject" (`PUT`) and "stale record sequence"
/// (`PUT`/`DELETE`/`POST`) — see `server.ts`. Anything else we don't
/// recognize falls back to `NameConflict` so callers still get an actionable
/// name-scoped error rather than a bare unexpected-status.
fn classify_conflict(name: &str, body: String) -> LinkError {
    let message = serde_json::from_str::<ErrorBody>(&body)
        .map(|parsed| parsed.error)
        .unwrap_or_default();
    if message.contains("stale") {
        LinkError::StaleSequence {
            name: name.to_string(),
            body,
        }
    } else {
        LinkError::NameConflict {
            name: name.to_string(),
            body,
        }
    }
}
