//! TC-1482: `GET /admin/stats`, a read-only list of the wallet addresses that
//! hold data on this node, for the scoreboard's "protocol users" figure.
//!
//! # Authentication
//!
//! A dedicated bearer token, `NODE_STATS_READ_TOKEN`, separate from
//! `TINYCLOUD_ADMIN_SECRET`. The two never open each other's routes:
//!
//! - the admin secret is refused here, and this token is refused by every
//!   `AdminAuth` route (`/admin/quota*`, `/admin/usage`), because each guard
//!   compares only against its own secret;
//! - if both are set to the same value, this route is disabled, so one value
//!   can never open both surfaces.
//!
//! When the token is unset, empty or whitespace-only the route is disabled and
//! answers exactly as an unknown route does (a 404 from the default catcher),
//! whatever the request carries. A missing, malformed or wrong credential is a
//! bare 401 with no detail. The comparison hashes both sides to fixed-length
//! SHA-256 digests and compares those in constant time, so neither the content
//! nor the length of the token is observable through timing.
//!
//! # Logging
//!
//! Neither the token nor an address is ever written anywhere. The guard's
//! error strings are constants, a failed query logs a constant message without
//! the database error, and the handler never records a space id with request
//! telemetry. The request logger records the route template only. The response
//! carries `Cache-Control: no-store`.
//!
//! # Failure
//!
//! The consumer (OpenKey) makes no partial use of a response, so the route
//! never returns a partial list: a result past the bounds in
//! `tinycloud_core::data_owners` (200,000 owners, 400,000 spaces read) is a
//! bare `507`, and a database failure a bare `500`.

use rocket::{
    http::{Header, Status},
    request::{FromRequest, Outcome, Request},
    response::{self, Responder, Response},
    serde::json::Json,
    State,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use tinycloud_core::data_owners::DataOwnersError;

use crate::TinyCloud;

/// The environment variable that carries the read-only stats token.
pub const STATS_TOKEN_ENV: &str = "NODE_STATS_READ_TOKEN";

/// Constant-time equality of two secrets of any length.
fn secrets_match(a: &str, b: &str) -> bool {
    Sha256::digest(a.as_bytes())
        .ct_eq(&Sha256::digest(b.as_bytes()))
        .into()
}

/// The configured stats token, or `None` when the route is disabled: unset,
/// empty or whitespace-only, not valid UTF-8, or equal to the admin secret.
fn configured_token() -> Option<String> {
    let token = std::env::var(STATS_TOKEN_ENV).ok()?;
    if token.trim().is_empty() {
        return None;
    }
    if let Ok(admin) = std::env::var("TINYCLOUD_ADMIN_SECRET") {
        if secrets_match(&token, &admin) {
            return None;
        }
    }
    Some(token)
}

/// Request guard: `Authorization: Bearer <NODE_STATS_READ_TOKEN>`.
pub struct StatsAuth;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for StatsAuth {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Disabled: indistinguishable from a route that does not exist.
        let Some(token) = configured_token() else {
            return Outcome::Forward(Status::NotFound);
        };
        match request
            .headers()
            .get_one("Authorization")
            .and_then(|header| header.strip_prefix("Bearer "))
        {
            Some(presented) if secrets_match(presented, &token) => Outcome::Success(StatsAuth),
            _ => Outcome::Error((Status::Unauthorized, "unauthorized")),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsResponse {
    /// Lowercase `0x` + 40 hex digit addresses, sorted ascending. Always the
    /// complete list: a result past the bounds is an error, never a partial
    /// `200`.
    owners: Vec<String>,
    count: usize,
    generated_at: String,
}

/// A JSON body that no cache may store.
pub struct NoStore<R>(R);

impl<'r, 'o: 'r, R: Responder<'r, 'o>> Responder<'r, 'o> for NoStore<R> {
    fn respond_to(self, request: &'r Request<'_>) -> response::Result<'o> {
        Response::build_from(self.0.respond_to(request)?)
            .header(Header::new("Cache-Control", "no-store"))
            .ok()
    }
}

/// The distinct owner addresses that hold data beyond the automatic `account`
/// space. One aggregate statement; see `tinycloud_core::data_owners`.
#[get("/admin/stats")]
pub async fn get_stats(
    _auth: StatsAuth,
    tinycloud: &State<TinyCloud>,
) -> Result<NoStore<Json<StatsResponse>>, Status> {
    let owners = tinycloud.data_owners().await.map_err(|error| {
        // Constant messages only: the error text is not needed here and
        // nothing derived from the data may reach the logs (TC-961).
        match error {
            DataOwnersError::TooLarge => {
                ::tracing::error!("admin stats result exceeds its bound");
                Status::InsufficientStorage
            }
            DataOwnersError::Db(_) => {
                ::tracing::error!("admin stats query failed");
                Status::InternalServerError
            }
        }
    })?;
    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| Status::InternalServerError)?;
    Ok(NoStore(Json(StatsResponse {
        count: owners.len(),
        owners,
        generated_at,
    })))
}
