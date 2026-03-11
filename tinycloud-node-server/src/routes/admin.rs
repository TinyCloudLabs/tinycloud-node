use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
    serde::json::Json,
    State,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use subtle::ConstantTimeEq;

use crate::quota::QuotaCache;
use crate::TinyCloud;

/// Request guard that validates `Authorization: Bearer <TINYCLOUD_ADMIN_SECRET>`.
pub struct AdminAuth;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminAuth {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let secret = match std::env::var("TINYCLOUD_ADMIN_SECRET") {
            Ok(s) if !s.is_empty() => s,
            _ => return Outcome::Error((Status::ServiceUnavailable, "Admin API not configured")),
        };

        let header = match request.headers().get_one("Authorization") {
            Some(h) => h,
            None => return Outcome::Error((Status::Unauthorized, "Missing Authorization header")),
        };

        let token = match header.strip_prefix("Bearer ") {
            Some(t) => t,
            None => return Outcome::Error((Status::Unauthorized, "Invalid Authorization format")),
        };

        if token.as_bytes().ct_eq(secret.as_bytes()).into() {
            Outcome::Success(AdminAuth)
        } else {
            Outcome::Error((Status::Unauthorized, "Invalid admin secret"))
        }
    }
}

#[derive(Deserialize)]
pub struct SetQuotaRequest {
    pub limit_bytes: u64,
}

#[derive(Serialize)]
pub struct QuotaResponse {
    pub space_id: String,
    pub override_bytes: Option<u64>,
    pub effective_limit_bytes: Option<u64>,
    pub current_usage_bytes: Option<u64>,
}

#[derive(Serialize)]
pub struct QuotaListResponse {
    pub overrides: HashMap<String, u64>,
    pub default_limit_bytes: Option<u64>,
}

#[put("/admin/quota/<space_id>", data = "<body>")]
pub async fn set_quota(
    _auth: AdminAuth,
    space_id: &str,
    body: Json<SetQuotaRequest>,
    quota_cache: &State<QuotaCache>,
) -> Result<Json<QuotaResponse>, (Status, String)> {
    let sid: tinycloud_auth::resource::SpaceId = space_id
        .parse()
        .map_err(|_| (Status::BadRequest, "Invalid space ID".into()))?;
    quota_cache.set_limit(&sid, body.limit_bytes).await;
    Ok(Json(QuotaResponse {
        space_id: space_id.to_string(),
        override_bytes: Some(body.limit_bytes),
        effective_limit_bytes: Some(body.limit_bytes),
        current_usage_bytes: None,
    }))
}

#[delete("/admin/quota/<space_id>")]
pub async fn delete_quota(
    _auth: AdminAuth,
    space_id: &str,
    quota_cache: &State<QuotaCache>,
) -> Result<Json<QuotaResponse>, (Status, String)> {
    let sid: tinycloud_auth::resource::SpaceId = space_id
        .parse()
        .map_err(|_| (Status::BadRequest, "Invalid space ID".into()))?;
    quota_cache.remove_limit(&sid).await;
    let effective = quota_cache.default_limit().map(|l| l.as_u64());
    Ok(Json(QuotaResponse {
        space_id: space_id.to_string(),
        override_bytes: None,
        effective_limit_bytes: effective,
        current_usage_bytes: None,
    }))
}

#[get("/admin/quota/<space_id>")]
pub async fn get_quota(
    _auth: AdminAuth,
    space_id: &str,
    quota_cache: &State<QuotaCache>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<QuotaResponse>, (Status, String)> {
    let sid: tinycloud_auth::resource::SpaceId = space_id
        .parse()
        .map_err(|_| (Status::BadRequest, "Invalid space ID".into()))?;
    let override_bytes = quota_cache.get_override(&sid).await;
    let effective = quota_cache.get_limit(&sid).await.map(|l| l.as_u64());
    let usage = tinycloud
        .store_size(&sid)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;
    Ok(Json(QuotaResponse {
        space_id: space_id.to_string(),
        override_bytes,
        effective_limit_bytes: effective,
        current_usage_bytes: usage,
    }))
}

#[get("/admin/quota")]
pub async fn list_quotas(
    _auth: AdminAuth,
    quota_cache: &State<QuotaCache>,
) -> Json<QuotaListResponse> {
    let overrides = quota_cache.list_overrides().await;
    Json(QuotaListResponse {
        overrides,
        default_limit_bytes: quota_cache.default_limit().map(|l| l.as_u64()),
    })
}
