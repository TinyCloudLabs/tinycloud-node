//! TC-3443: `POST /session/retire`, sign-out by retiring the session key.
use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
    serde::json::Json,
    State,
};
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use tinycloud_core::models::session_retire::verify_retire_request;

use crate::{
    config::SessionRetireConfig,
    routes::public::{ClientIp, RateLimiter},
    TinyCloud,
};

/// What `/session/retire` needs: this node's DID (the request's audience),
/// how long a retire lasts, and its own per-IP limiter.
pub struct SessionRetireRuntime {
    node_did: String,
    ttl: time::Duration,
    rate_limiter: RateLimiter,
}

impl SessionRetireRuntime {
    pub fn new(node_did: String, config: &SessionRetireConfig) -> Self {
        Self {
            node_did,
            ttl: config.ttl(),
            rate_limiter: RateLimiter::with_rate(
                config.rate_limit_per_minute,
                config.rate_limit_per_minute,
            ),
        }
    }
}

/// The `Authorization` header, if any. A missing header is refused by the
/// route with the same `session_retire_invalid:` body as a bad one.
pub struct RetireAuthorization(Option<String>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RetireAuthorization {
    type Error = ();
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(Self(
            request
                .headers()
                .get_one("Authorization")
                .map(str::to_owned),
        ))
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRetired {
    did: String,
    retired_at: String,
}

/// Retire the session key that signed the request. The header carries a
/// UCAN the session key issued to this node with exactly
/// `tinycloud.session/retire` on `urn:tinycloud:session:self`. From then
/// until the retire expires, the key can no longer use any delegated
/// authority and a delegation it issues is refused unless this node stored
/// it before the retire. Delegations it made earlier keep working; Revoke
/// ends those. A key holding no live grant on this node gets no record and
/// the same answer, `retiredAt` being now.
///
/// 200 `{"did", "retiredAt"}`, repeat calls answering the first retire
/// time; 401 `session_retire_invalid: <reason>`; 429 over the per-IP limit.
#[post("/session/retire")]
pub async fn retire_session(
    authorization: RetireAuthorization,
    client_ip: ClientIp,
    runtime: &State<SessionRetireRuntime>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<SessionRetired>, (Status, String)> {
    runtime
        .rate_limiter
        .check(client_ip.0)
        .map_err(|status| (status, "Rate limit exceeded".to_string()))?;
    let header = authorization.0.ok_or_else(|| {
        (
            Status::Unauthorized,
            "session_retire_invalid: the Authorization header is missing".to_string(),
        )
    })?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let did = verify_retire_request(&header, &runtime.node_did, now)
        .await
        .map_err(|error| (Status::Unauthorized, error.to_string()))?;
    let retired_at = tinycloud
        .retire_session(&did, runtime.ttl)
        .await
        .map_err(|error| {
            ::tracing::warn!(event = "session_retire_failed", %error);
            (
                Status::ServiceUnavailable,
                "session_retire_unavailable: the retire was not recorded".to_string(),
            )
        })?;
    let retired_at = retired_at.format(&Rfc3339).map_err(|_| {
        (
            Status::InternalServerError,
            "session_retire_unavailable: the retire time is unrepresentable".to_string(),
        )
    })?;
    Ok(Json(SessionRetired { did, retired_at }))
}
