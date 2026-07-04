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

#[derive(Serialize)]
pub struct SpaceUsage {
    pub space_id: String,
    pub usage_bytes: Option<u64>,
}

#[derive(Serialize)]
pub struct UsageResponse {
    pub spaces: Vec<SpaceUsage>,
    pub count: usize,
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
    // Never resolve via get_limit() here: it pulls from the remote quota
    // service, and that service calls this endpoint per owned space to compute
    // usage — on a cold cache the two recurse into a mutual-call storm.
    // Report only what is already known locally (override/cached, else the
    // env default).
    let effective = override_bytes.or_else(|| quota_cache.default_limit().map(|l| l.as_u64()));
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

/// Enumerate every space on the node with its authoritative metered usage
/// (`store_size`: KV block bytes + SQL/DuckDB artifact bytes, per #89).
/// Sorted by usage descending, with unknown (`null`) usage last. No
/// pagination: with a few hundred spaces this is a single pass.
#[get("/admin/usage")]
pub async fn get_usage(
    _auth: AdminAuth,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<UsageResponse>, (Status, String)> {
    let space_ids = tinycloud
        .list_space_ids()
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    let mut spaces = Vec::with_capacity(space_ids.len());
    for sid in space_ids {
        let usage = tinycloud
            .store_size(&sid)
            .await
            .map_err(|e| (Status::InternalServerError, e.to_string()))?;
        spaces.push(SpaceUsage {
            space_id: sid.to_string(),
            usage_bytes: usage,
        });
    }

    // Descending by usage; `None` (unknown) sorts last.
    sort_usage_desc_nulls_last(&mut spaces);

    let count = spaces.len();
    Ok(Json(UsageResponse { spaces, count }))
}

/// Sort spaces by usage descending, with unknown (`None`) usage last.
fn sort_usage_desc_nulls_last(spaces: &mut [SpaceUsage]) {
    spaces.sort_by(|a, b| match (a.usage_bytes, b.usage_bytes) {
        (Some(x), Some(y)) => y.cmp(&x),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
}

#[cfg(test)]
mod test {
    use super::*;

    fn su(space_id: &str, usage_bytes: Option<u64>) -> SpaceUsage {
        SpaceUsage {
            space_id: space_id.to_string(),
            usage_bytes,
        }
    }

    #[tokio::test]
    async fn sort_orders_desc_with_nulls_last() {
        let mut spaces = vec![
            su("a", Some(10)),
            su("b", None),
            su("c", Some(100)),
            su("d", None),
            su("e", Some(50)),
        ];
        sort_usage_desc_nulls_last(&mut spaces);
        let order: Vec<(&str, Option<u64>)> = spaces
            .iter()
            .map(|s| (s.space_id.as_str(), s.usage_bytes))
            .collect();
        assert_eq!(
            order,
            vec![
                ("c", Some(100)),
                ("e", Some(50)),
                ("a", Some(10)),
                ("b", None),
                ("d", None),
            ]
        );
    }
}
