//! TC-3443: `POST /session/retire`, sign-out by retiring the session key.
use rocket::{
    data::{Data, ToByteUnit},
    http::Status,
    request::{FromRequest, Outcome, Request},
    serde::json::Json,
    State,
};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use tinycloud_auth::authorization::TinyCloudDelegation;
use tinycloud_core::{
    events::SerializedEvent,
    models::session_retire::{verify_retire_request, SessionRetireError, MAX_CARRIED_DELEGATIONS},
    util::DelegationInfo,
};

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
    /// Whether this node recorded the retire. `false`: it holds no live
    /// grant for the key and none was carried, so nothing was written.
    recorded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    /// Indexes of carried delegations left out because they had expired.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    skipped: Vec<usize>,
}

/// The optional request body: root delegations to the session key, each
/// encoded as `POST /delegate` takes it in its `Authorization` header.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetireBody {
    #[serde(default)]
    delegations: Vec<String>,
}

/// Largest request body read: room for [`MAX_CARRIED_DELEGATIONS`] roots.
const MAX_BODY_KIB: u64 = 512;

fn invalid(reason: impl std::fmt::Display) -> (Status, String) {
    (
        Status::Unauthorized,
        format!("session_retire_invalid: {reason}"),
    )
}

fn rfc3339(time: time::OffsetDateTime) -> Result<String, (Status, String)> {
    time.format(&Rfc3339).map_err(|_| {
        (
            Status::InternalServerError,
            "session_retire_unavailable: the retire time is unrepresentable".to_string(),
        )
    })
}

/// Retire the session key that signed the request. The header carries a
/// UCAN the session key issued to this node with exactly
/// `tinycloud.session/retire` on `urn:tinycloud:session:self`. From then
/// until the retire expires, the key can no longer use any delegated
/// authority and a delegation it issues is refused unless this node stored
/// it before the retire. Delegations it made earlier keep working; Revoke
/// ends those.
///
/// The optional JSON body `{"delegations": ["<delegation>", ...]}` carries
/// the session's root delegations, each encoded as `POST /delegate` takes
/// it, at most [`MAX_CARRIED_DELEGATIONS`]. The client must send every root
/// it holds for the key, posted or not: each is admitted as `/delegate`
/// admits it, inside the retire, so the retire covers it and posting it
/// later cannot bring the key back. Each must be to the retiring key; any
/// refusal refuses the whole request and writes nothing. A root neither
/// carried nor stored here is not covered. A carried root that has expired
/// is skipped and its index listed in `skipped`; one not valid yet is not
/// stored but its signature and issuer are checked and the retire lasts
/// until it expires.
///
/// 200 `{"did", "retiredAt", "recorded", "expiresAt"?, "skipped"?}`:
/// `recorded: false` when this node holds no live grant for the key and
/// none was carried, so nothing was written; a repeat call answers the
/// first retire time.
/// 401 `session_retire_invalid: <reason>`; 429 over the per-IP limit.
#[post("/session/retire", data = "<body>")]
pub async fn retire_session(
    authorization: RetireAuthorization,
    client_ip: ClientIp,
    body: Data<'_>,
    runtime: &State<SessionRetireRuntime>,
    tinycloud: &State<TinyCloud>,
    policy_v3: &State<crate::policy_v3::PolicyV3Runtime>,
) -> Result<Json<SessionRetired>, (Status, String)> {
    runtime
        .rate_limiter
        .check(client_ip.0)
        .map_err(|status| (status, "Rate limit exceeded".to_string()))?;
    let header = authorization
        .0
        .ok_or_else(|| invalid("the Authorization header is missing"))?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let did = verify_retire_request(&header, &runtime.node_did, now)
        .await
        .map_err(|error| (Status::Unauthorized, error.to_string()))?;
    let body = body
        .open(MAX_BODY_KIB.kibibytes())
        .into_string()
        .await
        .map_err(|_| invalid("the body could not be read"))?;
    if !body.is_complete() {
        return Err(invalid("the body is too large"));
    }
    let body = if body.trim().is_empty() {
        RetireBody::default()
    } else {
        serde_json::from_str::<RetireBody>(&body)
            .map_err(|error| invalid(format!("the body is not valid JSON: {error}")))?
    };
    if body.delegations.len() > MAX_CARRIED_DELEGATIONS {
        return Err(invalid(format!(
            "at most {MAX_CARRIED_DELEGATIONS} delegations may be carried"
        )));
    }
    let mut carried = Vec::with_capacity(body.delegations.len());
    for (index, encoded) in body.delegations.iter().enumerate() {
        let delegation =
            SerializedEvent::<DelegationInfo>::from_header_ser::<TinyCloudDelegation>(encoded)
                .map_err(|error| invalid(format!("delegation {index}: {error}")))?;
        // As `/delegate`: the policy/v3 admission rules apply here too.
        if let Err(error) = policy_v3
            .ordinary_admission_allowed(tinycloud.inner(), &delegation)
            .await
        {
            let (status, message) = crate::policy_v3::authorization_failure(error);
            return Err(if status.code >= 500 {
                (status, message)
            } else {
                invalid(format!("delegation {index}: {message}"))
            });
        }
        carried.push(delegation);
    }
    let outcome = tinycloud
        .retire_session(&did, runtime.ttl, carried)
        .await
        .map_err(|error| match error {
            SessionRetireError::Invalid(_) => (Status::Unauthorized, error.to_string()),
            SessionRetireError::Unavailable(_) => {
                ::tracing::warn!(event = "session_retire_failed", %error);
                (
                    Status::ServiceUnavailable,
                    "session_retire_unavailable: the retire was not recorded".to_string(),
                )
            }
        })?;
    Ok(Json(SessionRetired {
        did,
        retired_at: rfc3339(outcome.retired_at)?,
        recorded: outcome.recorded(),
        expires_at: outcome.expires_at.map(rfc3339).transpose()?,
        skipped: outcome.skipped,
    }))
}
