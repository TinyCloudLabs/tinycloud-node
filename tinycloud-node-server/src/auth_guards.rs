use anyhow::Result;
use rocket::{
    data::{Capped, FromData},
    futures::io::AsyncRead,
    http::{ContentType, Header, HeaderMap, Status},
    request::{FromRequest, Outcome, Request},
    response::{Responder, Response},
    serde::json::Json,
    Data,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::Instant;
use tinycloud_auth::{
    authorization::{EncodingError, HeaderEncode},
    ipld_core::cid::Cid,
    resource::SpaceId,
};
use tinycloud_core::{
    hash::Hash,
    types::Metadata,
    util::{Capability, DelegationInfo},
    InvocationOutcome,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{info_span, Instrument};

#[derive(Debug)]
pub enum DataHolder<O, M = O> {
    None,
    One(O),
    Many(Vec<M>),
}

#[derive(Debug)]
pub struct InvOut<R>(pub InvocationOutcome<R>);

pub type DataIn<'a> = DataHolder<Data<'a>, (SpaceId, String, Metadata, Capped<&'a [u8]>)>;
pub type DataOut<R> = DataHolder<InvOut<R>>;

#[derive(Serialize)]
struct KvBatchWriteResponse {
    written: Vec<String>,
    count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KvBatchReadResponse {
    results: Vec<KvBatchReadResponseItem>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KvBatchReadResponseItem {
    key: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<KvBatchReadError>,
}

#[derive(Serialize)]
struct KvBatchReadError {
    code: &'static str,
    message: String,
}

fn kv_batch_read_response(items: Vec<tinycloud_core::KvBatchReadItem>) -> KvBatchReadResponse {
    let results = items
        .into_iter()
        .map(|item| match item.value {
            Some(value) => {
                let mut headers = filter_stored_object_metadata(value.metadata).0;
                headers.insert("etag".to_string(), kv_etag(value.hash));
                if let Some(data) = value.data.as_ref() {
                    headers.insert("content-length".to_string(), data.len().to_string());
                }
                KvBatchReadResponseItem {
                    key: item.path.to_string(),
                    ok: true,
                    data_base64: value.data.map(base64::encode),
                    headers: Some(headers),
                    error: None,
                }
            }
            None => KvBatchReadResponseItem {
                key: item.path.to_string(),
                ok: false,
                data_base64: None,
                headers: None,
                error: Some(KvBatchReadError {
                    code: "KV_NOT_FOUND",
                    message: format!("Key not found: {}", item.path),
                }),
            },
        })
        .collect();
    KvBatchReadResponse { results }
}

struct KvListResponse(Vec<tinycloud_auth::resource::Path>, bool, Option<String>);

impl<'r> Responder<'r, 'static> for KvListResponse {
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'static> {
        let mut response = Json(self.0).respond_to(request)?;
        response.set_header(Header::new("x-tinycloud-truncated", self.1.to_string()));
        if let Some(next_cursor) = self.2 {
            response.set_header(Header::new("x-tinycloud-next-cursor", next_cursor));
        }
        Ok(response)
    }
}

struct KvMutationResponse(Option<Hash>);

fn kv_etag(hash: Hash) -> String {
    format!("\"blake3-{}\"", hex::encode(hash.as_ref()))
}

impl<'r> Responder<'r, 'static> for KvMutationResponse {
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'static> {
        let mut response = ().respond_to(request)?;
        if let Some(hash) = self.0 {
            response.set_header(Header::new("ETag", kv_etag(hash)));
        }
        Ok(response)
    }
}

struct KvMetadataResponse(Metadata, Hash);

impl<'r> Responder<'r, 'static> for KvMetadataResponse {
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'static> {
        let mut response = ObjectHeaders(self.0).respond_to(request)?;
        response.set_header(Header::new("ETag", kv_etag(self.1)));
        Ok(response)
    }
}

#[async_trait]
impl<'r> FromData<'r> for DataIn<'r> {
    type Error = anyhow::Error;

    async fn from_data(
        req: &'r Request<'_>,
        data: Data<'r>,
    ) -> rocket::outcome::Outcome<Self, (Status, Self::Error), (Data<'r>, Status)> {
        let req_span = req
            .local_cache(|| Option::<crate::tracing::TracingSpan>::None)
            .as_ref()
            .unwrap();
        let span = info_span!(parent: &req_span.0, "data_in");
        // Instrumenting async block to handle yielding properly
        async move {
            let timer = crate::prometheus::enabled().then(|| {
                crate::prometheus::AUTHORIZATION_HISTOGRAM
                    .with_label_values(&["invoke"])
                    .start_timer()
            });

            let res = rocket::outcome::Outcome::Success(DataIn::One(data));

            if let Some(timer) = timer {
                timer.observe_duration();
            }
            res
        }
        .instrument(span)
        .await
    }
}

impl<'r, R> Responder<'r, 'static> for InvOut<R>
where
    R: 'static + AsyncRead + Send,
{
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'static> {
        match self.0 {
            InvocationOutcome::KvList(list, truncated, next_cursor) => {
                KvListResponse(list, truncated, next_cursor).respond_to(request)
            }
            InvocationOutcome::KvDelete(hash) => KvMutationResponse(hash).respond_to(request),
            InvocationOutcome::KvMetadata(meta) => meta
                .map(|(metadata, hash)| KvMetadataResponse(metadata, hash))
                .respond_to(request),
            InvocationOutcome::KvWrite(hash) => KvMutationResponse(Some(hash)).respond_to(request),
            InvocationOutcome::KvBatchWrite(written) => {
                let written = written
                    .into_iter()
                    .map(|path| path.to_string())
                    .collect::<Vec<_>>();
                Json(KvBatchWriteResponse {
                    count: written.len(),
                    written,
                })
                .respond_to(request)
            }
            InvocationOutcome::KvBatchRead(items) => {
                Json(kv_batch_read_response(items)).respond_to(request)
            }
            InvocationOutcome::KvRead(data) => data
                .map(|(md, hash, c)| KVResponse(c, md, hash))
                .respond_to(request),
            InvocationOutcome::OpenSessions(sessions) => Json(
                sessions
                    .into_iter()
                    .map(|(hash, del)| {
                        Ok((
                            hash.to_cid(0x55).to_string(),
                            CapJsonRep::from_delegation(del)?,
                        ))
                    })
                    .collect::<Result<HashMap<String, CapJsonRep>>>()
                    .map_err(|_| Status::InternalServerError)?,
            )
            .respond_to(request),
            InvocationOutcome::DelegationChain(chain) => Json(
                chain
                    .into_iter()
                    .map(|del| Ok(CapJsonRep::from_delegation(del)?))
                    .collect::<Result<Vec<CapJsonRep>>>()
                    .map_err(|_| Status::InternalServerError)?,
            )
            .respond_to(request),
            InvocationOutcome::SqlResult(json) => Json(json).respond_to(request),
            InvocationOutcome::SqlExport(data) => Response::build()
                .header(ContentType::new("application", "x-sqlite3"))
                .sized_body(data.len(), std::io::Cursor::new(data))
                .ok(),
            InvocationOutcome::DuckDbResult(json) => Json(json).respond_to(request),
            InvocationOutcome::DuckDbExport(data) => Response::build()
                .header(ContentType::new("application", "x-duckdb"))
                .sized_body(data.len(), std::io::Cursor::new(data))
                .ok(),
            InvocationOutcome::DuckDbArrow(data) => Response::build()
                .header(ContentType::new("application", "vnd.apache.arrow.stream"))
                .sized_body(data.len(), std::io::Cursor::new(data))
                .ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;
    use rocket::local::asynchronous::Client;
    use tinycloud_core::{hash::hash, KvBatchReadItem, KvBatchReadValue};

    #[test]
    fn batch_read_response_keeps_successes_and_missing_keys_in_order() {
        let response = kv_batch_read_response(vec![
            KvBatchReadItem {
                path: "found".parse().unwrap(),
                value: Some(KvBatchReadValue {
                    metadata: Metadata(BTreeMap::from([(
                        "content-type".to_string(),
                        "text/plain".to_string(),
                    )])),
                    hash: hash(b"hello"),
                    data: Some(b"hello".to_vec()),
                }),
            },
            KvBatchReadItem {
                path: "missing".parse().unwrap(),
                value: None,
            },
        ]);

        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["results"][0]["key"], "found");
        assert_eq!(json["results"][0]["ok"], true);
        assert_eq!(json["results"][0]["dataBase64"], "aGVsbG8=");
        assert_eq!(json["results"][0]["headers"]["content-length"], "5");
        assert_eq!(json["results"][1]["key"], "missing");
        assert_eq!(json["results"][1]["ok"], false);
        assert_eq!(json["results"][1]["error"]["code"], "KV_NOT_FOUND");
    }

    #[test]
    fn object_response_drops_hop_by_hop_headers() {
        for header in NON_REPLAYABLE_OBJECT_HEADERS {
            assert!(!is_replayable_object_header(header));
        }
        assert!(is_replayable_object_header("content-type"));
    }

    #[test]
    fn stored_object_metadata_allows_only_safe_headers() {
        let metadata = filter_stored_object_metadata(Metadata(BTreeMap::from([
            ("content-type".to_string(), "text/plain".to_string()),
            ("content-encoding".to_string(), "gzip".to_string()),
            ("content-language".to_string(), "en".to_string()),
            ("content-disposition".to_string(), "inline".to_string()),
            ("x-tinycloud-meta-owner".to_string(), "alice".to_string()),
            ("authorization".to_string(), "Bearer secret".to_string()),
            ("cookie".to_string(), "session=secret".to_string()),
            ("user-agent".to_string(), "client".to_string()),
            ("content-length".to_string(), "999".to_string()),
            ("transfer-encoding".to_string(), "chunked".to_string()),
            (
                "cache-control".to_string(),
                "public, max-age=31536000".to_string(),
            ),
            (
                "cdn-cache-control".to_string(),
                "public, max-age=31536000".to_string(),
            ),
        ])));

        assert_eq!(
            metadata.0,
            BTreeMap::from([
                ("content-type".to_string(), "text/plain".to_string()),
                ("content-encoding".to_string(), "gzip".to_string()),
                ("content-language".to_string(), "en".to_string()),
                ("content-disposition".to_string(), "inline".to_string()),
                ("x-tinycloud-meta-owner".to_string(), "alice".to_string()),
            ])
        );
    }

    #[get("/")]
    fn authenticated_stream() -> KVResponse<Cursor<Vec<u8>>> {
        let body = vec![b'a'; 32 * 1024 * 1024];
        KVResponse(
            tinycloud_core::storage::Content::new(body.len() as u64, Cursor::new(body)),
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
            hash(b"authenticated-stream"),
        )
    }

    #[tokio::test]
    async fn authenticated_response_headers_and_body_are_observed() -> Result<()> {
        let client =
            Client::tracked(rocket::build().mount("/", rocket::routes![authenticated_stream]))
                .await?;
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
    async fn kv_responder_sets_streaming_postconditions() -> Result<()> {
        let client = Client::tracked(rocket::build()).await?;
        let request = client.get("/");
        let body = vec![b'k'; 32 * 1024];
        let response = KVResponse::new(
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
            hash(b"direct-authenticated-stream"),
            tinycloud_core::storage::Content::new(body.len() as u64, Cursor::new(body)),
        )
        .respond_to(request.inner())
        .map_err(|status| anyhow::anyhow!("KVResponse failed: {status}"))?;

        assert_eq!(response.body().max_chunk_size(), STREAM_MAX_CHUNK_SIZE);
        assert_eq!(response.headers().get_one("Content-Length"), Some("32768"));
        assert!(response.headers().get_one("Transfer-Encoding").is_none());
        Ok(())
    }
}

impl<'r, R> Responder<'r, 'static> for DataOut<R>
where
    R: 'static + AsyncRead + Send,
{
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'static> {
        let start = Instant::now();
        let response = match self {
            DataHolder::None => ().respond_to(request),
            DataHolder::One(inv) => inv.respond_to(request),
            DataHolder::Many(_invs) => Err(Status::NotImplemented),
        };
        crate::prometheus::observe_stage(
            crate::prometheus::InvocationStage::ResponseHandling,
            crate::prometheus::StageOutcome::from(response.is_ok()),
            start.elapsed(),
        );
        response
    }
}

#[derive(Serialize, Deserialize)]
pub struct CapJsonRep {
    pub capabilities: Vec<Capability>,
    pub delegator: String,
    pub delegate: String,
    pub parents: Vec<Cid>,
    raw: String,
}

impl CapJsonRep {
    pub fn from_delegation(d: DelegationInfo) -> Result<Self, EncodingError> {
        Ok(Self {
            capabilities: d.capabilities,
            delegator: d.delegator,
            delegate: d.delegate,
            parents: d.parents,
            raw: d.delegation.encode()?,
        })
    }
}

pub struct ObjectHeaders(pub Metadata);

pub(crate) const STREAM_MAX_CHUNK_SIZE: usize = 256 * 1024;

const STORED_OBJECT_HEADERS: &[&str] = &[
    "content-type",
    "content-encoding",
    "content-language",
    "content-disposition",
];

const X_TINYCLOUD_META_PREFIX: &str = "x-tinycloud-meta-";

/// Allocation-free, ASCII-case-insensitive check for whether `name` is
/// permitted to become stored object metadata (TC-410).
pub(crate) fn is_storable_object_header(name: &str) -> bool {
    STORED_OBJECT_HEADERS
        .iter()
        .any(|header| name.eq_ignore_ascii_case(header))
        || name
            .as_bytes()
            .get(..X_TINYCLOUD_META_PREFIX.len())
            .map(|prefix| prefix.eq_ignore_ascii_case(X_TINYCLOUD_META_PREFIX.as_bytes()))
            .unwrap_or(false)
}

pub(crate) fn filter_stored_object_metadata(metadata: Metadata) -> Metadata {
    Metadata(
        metadata
            .0
            .into_iter()
            .filter(|(key, _)| is_storable_object_header(key))
            .collect(),
    )
}

const NON_REPLAYABLE_OBJECT_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub(crate) fn is_replayable_object_header(name: &str) -> bool {
    is_storable_object_header(name)
        && !NON_REPLAYABLE_OBJECT_HEADERS
            .iter()
            .any(|header| name.eq_ignore_ascii_case(header))
}

/// Lifetime-bound `/invoke` request guard (TC-410). Borrows the last
/// Rocket-parsed value for authorization-adjacent/control headers with no
/// allocation, and owns only the small allowlist of headers permitted to
/// become stored object metadata. `Authorization`, `Cookie`, and every other
/// unlisted header are never copied here; `Authorization`'s value is read
/// only by [`crate::authorization::AuthHeaderGetter`].
pub struct InvokeHeaders<'r> {
    pub accept: Option<&'r str>,
    pub content_type: Option<&'r str>,
    pub if_match: Option<&'r str>,
    pub if_none_match: Option<&'r str>,
    pub expected_version: Option<&'r str>,
    pub max_response_bytes: Option<&'r str>,
    pub limit: Option<&'r str>,
    pub cursor: Option<&'r str>,
    pub metadata: Metadata,
}

/// A header nominated by a comma-separated `Connection` token is hop-by-hop
/// for this request and must never be persisted, even if it would otherwise
/// be storable object metadata. Scans `Connection` values directly instead
/// of allocating a token set.
fn connection_nominates(headers: &HeaderMap<'_>, name: &str) -> bool {
    headers
        .get("connection")
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(name))
}

#[async_trait]
impl<'r> FromRequest<'r> for InvokeHeaders<'r> {
    type Error = anyhow::Error;
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();

        let mut metadata = BTreeMap::new();
        for header in headers.iter() {
            let name = header.name.as_str();
            if is_storable_object_header(name) && !connection_nominates(headers, name) {
                metadata.insert(name.to_string(), header.value.to_string());
            }
        }

        Outcome::Success(InvokeHeaders {
            accept: headers.get("accept").last(),
            content_type: headers.get("content-type").last(),
            if_match: headers.get("if-match").last(),
            if_none_match: headers.get("if-none-match").last(),
            expected_version: headers.get("x-tinycloud-expected-version").last(),
            max_response_bytes: headers.get("x-tinycloud-max-response-bytes").last(),
            limit: headers.get("x-tinycloud-limit").last(),
            cursor: headers.get("x-tinycloud-cursor").last(),
            metadata: Metadata(metadata),
        })
    }
}

impl<'r> Responder<'r, 'static> for ObjectHeaders {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'static> {
        let mut r = Response::build();
        for (k, v) in self.0 .0 {
            if is_replayable_object_header(&k) {
                r.header(Header::new(k, v));
            }
        }
        Ok(r.finalize())
    }
}

pub struct KVResponse<R>(tinycloud_core::storage::Content<R>, pub Metadata, pub Hash);

impl<R> KVResponse<R> {
    pub fn new(md: Metadata, hash: Hash, reader: tinycloud_core::storage::Content<R>) -> Self {
        Self(reader, md, hash)
    }
}

impl<'r, R> Responder<'r, 'static> for KVResponse<R>
where
    R: 'static + AsyncRead + Send,
{
    fn respond_to(self, r: &'r Request<'_>) -> rocket::response::Result<'static> {
        let KVResponse(content, metadata, hash) = self;
        let content_length = content.len();
        let etag = kv_etag(hash);
        Ok(Response::build_from(ObjectHeaders(metadata).respond_to(r)?)
            .header(Header::new("ETag", etag))
            .header(Header::new("Content-Length", content_length.to_string()))
            // must ensure that Metadata::respond_to does not set the body of the response
            .streamed_body(content.compat())
            .max_chunk_size(STREAM_MAX_CHUNK_SIZE)
            .finalize())
    }
}
