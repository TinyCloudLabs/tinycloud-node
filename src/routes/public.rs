use rocket::{
    futures::io::AsyncRead,
    http::{uri::fmt, Header, Status},
    request::{FromRequest, FromSegments, Outcome, Request},
    response::{Responder, Response},
    serde::json::Json,
    State,
};
use std::{collections::HashMap, net::IpAddr, sync::Mutex, time::Instant};
use tinycloud_core::storage::{Content, ImmutableReadStore};
use tinycloud_lib::resource::{Path, SpaceId};
use tokio_util::compat::FuturesAsyncReadCompatExt;

use crate::{config::PublicSpacesConfig, BlockStores, TinyCloud};
use tinycloud_core::types::Metadata;

/// A key path that allows dot-prefixed segments like `.well-known/profile`.
/// Unlike `std::path::PathBuf`, this does not reject hidden files/dirs.
pub struct RawKeyPath(pub String);

impl<'r> FromSegments<'r> for RawKeyPath {
    type Error = String;

    fn from_segments(
        segments: rocket::http::uri::Segments<'r, fmt::Path>,
    ) -> Result<Self, Self::Error> {
        let joined: String = segments.collect::<Vec<_>>().join("/");
        if joined.is_empty() {
            Err("Empty key path".to_string())
        } else {
            Ok(RawKeyPath(joined))
        }
    }
}

/// Check if a space is a public space based on its name.
pub fn is_public_space(space_id: &SpaceId) -> bool {
    space_id.name().as_str() == "public"
}

// --- Rate Limiter ---

pub struct RateLimiter {
    state: Mutex<HashMap<IpAddr, TokenBucket>>,
    tokens_per_second: f64,
    burst: u32,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(config: &PublicSpacesConfig) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            tokens_per_second: config.rate_limit_per_minute as f64 / 60.0,
            burst: config.rate_limit_burst,
        }
    }

    pub fn check(&self, ip: IpAddr) -> Result<(), Status> {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        let max_tokens = self.burst as f64 + self.tokens_per_second;

        let bucket = state.entry(ip).or_insert(TokenBucket {
            tokens: max_tokens,
            last_refill: now,
        });

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.tokens_per_second).min(max_tokens);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(Status::TooManyRequests)
        }
    }
}

// --- Request Guards ---

pub struct ClientIp(pub IpAddr);

#[async_trait]
impl<'r> FromRequest<'r> for ClientIp {
    type Error = ();
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.client_ip() {
            Some(ip) => Outcome::Success(ClientIp(ip)),
            None => Outcome::Error((Status::BadRequest, ())),
        }
    }
}

pub struct IfNoneMatch(pub String);

#[async_trait]
impl<'r> FromRequest<'r> for IfNoneMatch {
    type Error = ();
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one("If-None-Match") {
            Some(val) => Outcome::Success(IfNoneMatch(val.to_string())),
            None => Outcome::Forward(Status::NotFound),
        }
    }
}

// --- Response Types ---

const CACHE_CONTROL: &str = "public, max-age=60";
const CORS_ORIGIN: &str = "*";
const CORS_METHODS: &str = "GET, HEAD, OPTIONS";
const CORS_ALLOW_HEADERS: &str = "If-None-Match";
const CORS_EXPOSE_HEADERS: &str = "ETag, Content-Type, Content-Length";

/// Headers safe to expose on unauthenticated public endpoints.
/// Everything else (authorization, host, user-agent, etc.) is stripped.
const PUBLIC_SAFE_HEADERS: &[&str] = &["content-type", "content-encoding", "content-language"];

fn sanitized_metadata(md: &Metadata) -> impl Iterator<Item = (&String, &String)> {
    md.0.iter()
        .filter(|(k, _)| PUBLIC_SAFE_HEADERS.contains(&k.to_lowercase().as_str()))
}

fn add_public_headers(response: &mut Response<'_>, etag: Option<&str>) {
    response.set_header(Header::new("Cache-Control", CACHE_CONTROL));
    response.set_header(Header::new("Access-Control-Allow-Origin", CORS_ORIGIN));
    response.set_header(Header::new("Access-Control-Allow-Methods", CORS_METHODS));
    response.set_header(Header::new(
        "Access-Control-Allow-Headers",
        CORS_ALLOW_HEADERS,
    ));
    response.set_header(Header::new(
        "Access-Control-Expose-Headers",
        CORS_EXPOSE_HEADERS,
    ));
    if let Some(etag) = etag {
        response.set_header(Header::new("ETag", etag.to_string()));
    }
}

pub struct PublicKVResponse<R>(Content<R>, Metadata, String);

impl<'r, R> Responder<'r, 'static> for PublicKVResponse<R>
where
    R: 'static + AsyncRead + Send,
{
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'static> {
        let mut response = Response::build().streamed_body(self.0.compat()).finalize();
        for (k, v) in sanitized_metadata(&self.1) {
            response.set_header(Header::new(k.clone(), v.clone()));
        }
        add_public_headers(&mut response, Some(&self.2));
        Ok(response)
    }
}

pub struct NotModifiedResponse(String);

impl<'r> Responder<'r, 'static> for NotModifiedResponse {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'static> {
        let mut response = Response::build().status(Status::NotModified).finalize();
        add_public_headers(&mut response, Some(&self.0));
        Ok(response)
    }
}

pub struct PublicMetadataResponse(Metadata, String);

impl<'r> Responder<'r, 'static> for PublicMetadataResponse {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'static> {
        let mut response = Response::build().finalize();
        for (k, v) in sanitized_metadata(&self.0) {
            response.set_header(Header::new(k.clone(), v.clone()));
        }
        add_public_headers(&mut response, Some(&self.1));
        Ok(response)
    }
}

pub struct PublicListResponse(Json<Vec<Path>>);

impl<'r> Responder<'r, 'static> for PublicListResponse {
    fn respond_to(self, r: &'r Request<'_>) -> rocket::response::Result<'static> {
        let mut response = self.0.respond_to(r)?;
        add_public_headers(&mut response, None);
        Ok(response)
    }
}

// --- Routes ---

#[get("/public/<space_id>/kv/<key..>")]
pub async fn public_kv_get(
    space_id: &str,
    key: RawKeyPath,
    if_none_match: Option<IfNoneMatch>,
    client_ip: ClientIp,
    rate_limiter: &State<RateLimiter>,
    tinycloud: &State<TinyCloud>,
) -> Result<
    Result<PublicKVResponse<<BlockStores as ImmutableReadStore>::Readable>, NotModifiedResponse>,
    (Status, String),
> {
    rate_limiter
        .check(client_ip.0)
        .map_err(|s| (s, "Rate limit exceeded".to_string()))?;

    let space_id: SpaceId = space_id
        .parse()
        .map_err(|_| (Status::BadRequest, "Invalid space ID".to_string()))?;

    if !is_public_space(&space_id) {
        return Err((Status::Forbidden, "Not a public space".to_string()));
    }

    let key: Path = key
        .0
        .parse()
        .map_err(|_| (Status::BadRequest, "Invalid key".to_string()))?;

    let result = tinycloud
        .public_kv_get(&space_id, &key)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    match result {
        Some((md, hash, content)) => {
            let etag = format!("\"blake3-{}\"", hex::encode(hash.as_ref()));

            if let Some(IfNoneMatch(client_etag)) = &if_none_match {
                if client_etag == &etag {
                    return Ok(Err(NotModifiedResponse(etag)));
                }
            }

            Ok(Ok(PublicKVResponse(content, md, etag)))
        }
        None => Err((Status::NotFound, "Key not found".to_string())),
    }
}

#[head("/public/<space_id>/kv/<key..>")]
pub async fn public_kv_head(
    space_id: &str,
    key: RawKeyPath,
    if_none_match: Option<IfNoneMatch>,
    client_ip: ClientIp,
    rate_limiter: &State<RateLimiter>,
    tinycloud: &State<TinyCloud>,
) -> Result<Result<PublicMetadataResponse, NotModifiedResponse>, (Status, String)> {
    rate_limiter
        .check(client_ip.0)
        .map_err(|s| (s, "Rate limit exceeded".to_string()))?;

    let space_id: SpaceId = space_id
        .parse()
        .map_err(|_| (Status::BadRequest, "Invalid space ID".to_string()))?;

    if !is_public_space(&space_id) {
        return Err((Status::Forbidden, "Not a public space".to_string()));
    }

    let key: Path = key
        .0
        .parse()
        .map_err(|_| (Status::BadRequest, "Invalid key".to_string()))?;

    let result = tinycloud
        .public_kv_get(&space_id, &key)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    match result {
        Some((md, hash, _content)) => {
            let etag = format!("\"blake3-{}\"", hex::encode(hash.as_ref()));

            if let Some(IfNoneMatch(client_etag)) = &if_none_match {
                if client_etag == &etag {
                    return Ok(Err(NotModifiedResponse(etag)));
                }
            }

            Ok(Ok(PublicMetadataResponse(md, etag)))
        }
        None => Err((Status::NotFound, "Key not found".to_string())),
    }
}

#[get("/public/<space_id>/kv?<prefix>")]
pub async fn public_kv_list(
    space_id: &str,
    prefix: Option<&str>,
    client_ip: ClientIp,
    rate_limiter: &State<RateLimiter>,
    tinycloud: &State<TinyCloud>,
) -> Result<PublicListResponse, (Status, String)> {
    rate_limiter
        .check(client_ip.0)
        .map_err(|s| (s, "Rate limit exceeded".to_string()))?;

    let space_id: SpaceId = space_id
        .parse()
        .map_err(|_| (Status::BadRequest, "Invalid space ID".to_string()))?;

    if !is_public_space(&space_id) {
        return Err((Status::Forbidden, "Not a public space".to_string()));
    }

    let prefix_path: Path = prefix
        .unwrap_or("")
        .parse()
        .map_err(|_| (Status::BadRequest, "Invalid prefix".to_string()))?;

    let list = tinycloud
        .public_kv_list(&space_id, &prefix_path)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    Ok(PublicListResponse(Json(list)))
}

#[options("/public/<_space_id>/kv/<_key..>")]
pub async fn public_kv_options(_space_id: &str, _key: RawKeyPath) -> Status {
    Status::NoContent
}
