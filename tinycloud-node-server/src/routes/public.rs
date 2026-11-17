use rocket::{
    futures::io::AsyncRead,
    http::{uri::fmt, Header, Status},
    request::{FromRequest, FromSegments, Outcome, Request},
    response::{Responder, Response},
    serde::json::Json,
    State,
};
use std::{
    borrow::Borrow,
    collections::HashMap,
    hash::Hash,
    net::IpAddr,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};
use tinycloud_auth::resource::{Path, SpaceId};
use tinycloud_core::storage::{Content, ImmutableReadStore};
use tokio_util::compat::FuturesAsyncReadCompatExt;

use crate::{
    auth_guards::STREAM_MAX_CHUNK_SIZE,
    config::{InvocationConfig, PublicSpacesConfig},
    BlockStores, TinyCloud,
};
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

/// Token buckets for the public endpoints (per client IP) and, when
/// configured, for `/invoke` (per verified invoker).
pub struct RateLimiter {
    public: Buckets<IpAddr>,
    invokers: Option<InvokerLimit>,
}

/// The `/invoke` limit per verified invoker (TC-3216). In shadow mode (the
/// default) a request over it is counted and reported but admitted; enforced,
/// it is refused with `429`.
struct InvokerLimit {
    buckets: Buckets<String>,
    enforce: bool,
    report: Mutex<OverLimitReport>,
}

/// Over-limit `/invoke` requests not yet in a log line.
struct OverLimitReport {
    count: u64,
    since: Option<Instant>,
}

/// At most one `invoke_rate_limited` log line per this many seconds.
const OVER_LIMIT_REPORT_SECS: u64 = 60;

impl InvokerLimit {
    /// Count one over-limit request: the metric always, and a log line with
    /// the count so far when none was emitted in the last window. The line
    /// names no invoker, space or account.
    fn observe_over(&self, now: Instant) {
        let mode = if self.enforce { "enforce" } else { "shadow" };
        crate::prometheus::observe_invoke_rate_limited(mode);
        let mut report = self.report.lock().unwrap_or_else(PoisonError::into_inner);
        report.count += 1;
        let due = report.since.is_none_or(|since| {
            now.saturating_duration_since(since) >= Duration::from_secs(OVER_LIMIT_REPORT_SECS)
        });
        if due {
            tracing::warn!(
                event = "invoke_rate_limited",
                mode,
                count = report.count,
                window_s = OVER_LIMIT_REPORT_SECS,
                "invocations over the per-invoker rate limit"
            );
            report.count = 0;
            report.since = Some(now);
        }
    }
}

/// Most callers tracked at once per bucket family. A full bucket is the same
/// as no bucket, so full ones are forgotten first; past that, a new caller is
/// admitted untracked rather than growing the map.
const MAX_TRACKED_CALLERS: usize = 100_000;

struct Buckets<K> {
    state: Mutex<HashMap<K, TokenBucket>>,
    tokens_per_second: f64,
    burst: u32,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl<K: Eq + Hash> Buckets<K> {
    fn new(per_minute: u32, burst: u32) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            tokens_per_second: per_minute as f64 / 60.0,
            burst,
        }
    }

    /// Take one token for `key`, or return how long until one is available
    /// (`None` when the bucket never refills).
    fn take<Q>(&self, key: &Q, now: Instant) -> Result<(), Option<Duration>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ToOwned<Owned = K> + ?Sized,
    {
        self.with_bucket(key, now, |bucket| {
            self.available(bucket)?;
            bucket.tokens -= 1.0;
            Ok(())
        })
        .unwrap_or(Ok(()))
    }

    /// Whether `key` has a token now, spending none; the wait as
    /// [`take`](Self::take).
    fn peek<Q>(&self, key: &Q, now: Instant) -> Result<(), Option<Duration>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ToOwned<Owned = K> + ?Sized,
    {
        self.with_bucket(key, now, |bucket| self.available(bucket))
            .unwrap_or(Ok(()))
    }

    /// Spend one token for `key` whether or not it has one. Requests admitted
    /// together by [`peek`](Self::peek) can overdraw the bucket; the debt,
    /// bounded by one full bucket, is repaid by refill before the next
    /// admission.
    fn charge<Q>(&self, key: &Q, now: Instant)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ToOwned<Owned = K> + ?Sized,
    {
        let floor = -self.max_tokens();
        self.with_bucket(key, now, |bucket| {
            bucket.tokens = (bucket.tokens - 1.0).max(floor);
        });
    }

    fn max_tokens(&self) -> f64 {
        self.burst as f64 + self.tokens_per_second
    }

    /// `Ok` when `bucket` holds a whole token, else how long until it does.
    fn available(&self, bucket: &TokenBucket) -> Result<(), Option<Duration>> {
        if bucket.tokens >= 1.0 {
            Ok(())
        } else if self.tokens_per_second > 0.0 {
            Err(Some(Duration::from_secs_f64(
                (1.0 - bucket.tokens) / self.tokens_per_second,
            )))
        } else {
            Err(None)
        }
    }

    /// Run `f` on `key`'s bucket, refilled to `now`; a new key starts full.
    /// `None` when the key cannot be tracked (see [`MAX_TRACKED_CALLERS`]).
    fn with_bucket<Q, R>(
        &self,
        key: &Q,
        now: Instant,
        f: impl FnOnce(&mut TokenBucket) -> R,
    ) -> Option<R>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ToOwned<Owned = K> + ?Sized,
    {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let max_tokens = self.max_tokens();
        let refilled = |bucket: &TokenBucket| {
            let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
            (bucket.tokens + elapsed * self.tokens_per_second).min(max_tokens)
        };
        if !state.contains_key(key) {
            if state.len() >= MAX_TRACKED_CALLERS {
                state.retain(|_, bucket| refilled(bucket) < max_tokens);
                if state.len() >= MAX_TRACKED_CALLERS {
                    return None;
                }
            }
            state.insert(
                key.to_owned(),
                TokenBucket {
                    tokens: max_tokens,
                    last_refill: now,
                },
            );
        }
        let bucket = state.get_mut(key)?;
        bucket.tokens = refilled(bucket);
        bucket.last_refill = now;
        Some(f(bucket))
    }
}

impl RateLimiter {
    pub fn new(config: &PublicSpacesConfig) -> Self {
        Self {
            public: Buckets::new(config.rate_limit_per_minute, config.rate_limit_burst),
            invokers: None,
        }
    }

    /// Also limit `/invoke` per invoker, as `config` sets; a zero rate leaves
    /// it unlimited. A burst below one would refuse every request, so it is
    /// raised to one. Only `rate_limit_enforce` refuses; otherwise the limit
    /// is shadowed.
    pub fn with_invocation_limit(mut self, config: &InvocationConfig) -> Self {
        self.invokers = (config.rate_limit_per_minute > 0).then(|| InvokerLimit {
            buckets: Buckets::new(config.rate_limit_per_minute, config.rate_limit_burst.max(1)),
            enforce: config.rate_limit_enforce,
            report: Mutex::new(OverLimitReport {
                count: 0,
                since: None,
            }),
        });
        self
    }

    pub fn check(&self, ip: IpAddr) -> Result<(), Status> {
        self.public
            .take(&ip, Instant::now())
            .map_err(|_| Status::TooManyRequests)
    }

    /// Admit one `/invoke` request for `invoker` (a verified invocation's
    /// issuer) if its share has a token, spending none: the request is
    /// charged by [`charge_invoker`](Self::charge_invoker) once it proves not
    /// to be a replay, so a replayed copy of someone's request cannot spend
    /// their share. Over the limit and enforced, return the whole seconds to
    /// send as `Retry-After`; shadowed, count it and admit it.
    pub fn check_invoker(&self, invoker: &str) -> Result<(), u64> {
        let Some(limit) = &self.invokers else {
            return Ok(());
        };
        let now = Instant::now();
        let Err(wait) = limit.buckets.peek(invoker, now) else {
            return Ok(());
        };
        limit.observe_over(now);
        if !limit.enforce {
            return Ok(());
        }
        Err(wait.map_or(u64::MAX, |wait| wait.as_secs_f64().ceil().max(1.0) as u64))
    }

    /// Spend one of `invoker`'s tokens for a request [`check_invoker`]
    /// admitted that was not refused as a replay.
    ///
    /// [`check_invoker`]: Self::check_invoker
    pub fn charge_invoker(&self, invoker: &str) {
        if let Some(limit) = &self.invokers {
            limit.buckets.charge(invoker, Instant::now());
        }
    }
}

/// The node's [`RateLimiter`] for `/invoke`, when one is managed. Rockets
/// built without one (unit-test rockets) are not limited.
pub struct InvokeRateLimiter<'r>(pub Option<&'r RateLimiter>);

#[async_trait]
impl<'r> FromRequest<'r> for InvokeRateLimiter<'r> {
    type Error = ();
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(Self(request.rocket().state::<RateLimiter>()))
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
        let PublicKVResponse(content, metadata, etag) = self;
        let content_length = content.len();
        let mut response = Response::build()
            .streamed_body(content.compat())
            .max_chunk_size(STREAM_MAX_CHUNK_SIZE)
            .finalize();
        for (k, v) in sanitized_metadata(&metadata) {
            response.set_header(Header::new(k.clone(), v.clone()));
        }
        response.set_header(Header::new("Content-Length", content_length.to_string()));
        add_public_headers(&mut response, Some(&etag));
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
    tinycloud_core::request_telemetry::observe_space(&space_id);

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
    tinycloud_core::request_telemetry::observe_space(&space_id);

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
    tinycloud_core::request_telemetry::observe_space(&space_id);

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

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;
    use rocket::local::asynchronous::Client;
    use tinycloud_core::storage::Content;

    #[get("/")]
    fn public_stream() -> PublicKVResponse<Cursor<Vec<u8>>> {
        let body = vec![b'p'; 32 * 1024 * 1024];
        PublicKVResponse(
            Content::new(body.len() as u64, Cursor::new(body)),
            Metadata(
                [
                    (
                        "content-type".to_string(),
                        "application/octet-stream".to_string(),
                    ),
                    ("transfer-encoding".to_string(), "chunked".to_string()),
                ]
                .into_iter()
                .collect(),
            ),
            "\"public-stream\"".to_string(),
        )
    }

    #[tokio::test]
    async fn public_response_headers_and_body_are_observed() -> anyhow::Result<()> {
        let client =
            Client::tracked(rocket::build().mount("/", rocket::routes![public_stream])).await?;
        let response = client.get("/").dispatch().await;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.headers().get_one("Content-Length"),
            Some("33554432")
        );
        assert!(response.headers().get_one("Transfer-Encoding").is_none());
        assert_eq!(response.into_bytes().await.unwrap().len(), 32 * 1024 * 1024);
        Ok(())
    }

    #[tokio::test]
    async fn public_responder_sets_streaming_postconditions() -> anyhow::Result<()> {
        let client = Client::tracked(rocket::build()).await?;
        let request = client.get("/");
        let body = vec![b'p'; 32 * 1024];
        let response = PublicKVResponse(
            Content::new(body.len() as u64, Cursor::new(body)),
            Metadata(
                [
                    (
                        "content-type".to_string(),
                        "application/octet-stream".to_string(),
                    ),
                    ("transfer-encoding".to_string(), "chunked".to_string()),
                ]
                .into_iter()
                .collect(),
            ),
            "\"direct-public-stream\"".to_string(),
        )
        .respond_to(request.inner())
        .map_err(|status| anyhow::anyhow!("PublicKVResponse failed: {status}"))?;

        assert_eq!(response.body().max_chunk_size(), STREAM_MAX_CHUNK_SIZE);
        assert_eq!(response.headers().get_one("Content-Length"), Some("32768"));
        assert!(response.headers().get_one("Transfer-Encoding").is_none());
        Ok(())
    }

    const PUBLIC_ETAG: &str = "\"blake3-public\"";

    #[get("/etag-full")]
    fn public_etag_full() -> PublicKVResponse<Cursor<Vec<u8>>> {
        PublicKVResponse(
            Content::new(2, Cursor::new(b"ok".to_vec())),
            Metadata(Default::default()),
            PUBLIC_ETAG.to_string(),
        )
    }

    #[get("/etag-304")]
    fn public_etag_not_modified() -> NotModifiedResponse {
        NotModifiedResponse(PUBLIC_ETAG.to_string())
    }

    #[get("/etag-metadata")]
    fn public_etag_metadata() -> PublicMetadataResponse {
        PublicMetadataResponse(Metadata(Default::default()), PUBLIC_ETAG.to_string())
    }

    #[get("/list")]
    fn public_list() -> PublicListResponse {
        PublicListResponse(Json(Vec::new()))
    }

    /// TC-1432: public KV reads (200, 304, metadata) keep `public, max-age=60`
    /// and gain `no-transform`; the list has no ETag and is unchanged.
    #[tokio::test]
    async fn public_etag_responses_add_no_transform_and_keep_cache_policy() -> anyhow::Result<()> {
        let client = Client::tracked(crate::attach_response_fairings(rocket::build().mount(
            "/",
            rocket::routes![
                public_etag_full,
                public_etag_not_modified,
                public_etag_metadata,
                public_list
            ],
        )))
        .await?;
        for (path, status) in [
            ("/etag-full", Status::Ok),
            ("/etag-304", Status::NotModified),
            ("/etag-metadata", Status::Ok),
        ] {
            let response = client.get(path).dispatch().await;
            assert_eq!(response.status(), status, "{path}");
            assert_eq!(
                response.headers().get_one("ETag"),
                Some(PUBLIC_ETAG),
                "{path}"
            );
            assert_eq!(
                response.headers().get_one("Cache-Control"),
                Some("public, max-age=60, no-transform"),
                "{path}"
            );
        }
        let list = client.get("/list").dispatch().await;
        assert!(list.headers().get_one("ETag").is_none());
        assert_eq!(
            list.headers().get_one("Cache-Control"),
            Some("public, max-age=60")
        );
        Ok(())
    }
}
