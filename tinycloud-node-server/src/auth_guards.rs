use anyhow::Result;
use rocket::{
    data::{Capped, FromData},
    futures::io::AsyncRead,
    http::{ContentType, Header, Status},
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
                let mut headers = value.metadata.0;
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

struct KvListResponse(Vec<tinycloud_auth::resource::Path>, bool);

impl<'r> Responder<'r, 'static> for KvListResponse {
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'static> {
        let mut response = Json(self.0).respond_to(request)?;
        response.set_header(Header::new("x-tinycloud-truncated", self.1.to_string()));
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
            InvocationOutcome::KvList(list, truncated) => {
                KvListResponse(list, truncated).respond_to(request)
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
    fn streamed_response_uses_configured_max_chunk_size() {
        let response = Response::build()
            .streamed_body(tokio::io::empty())
            .max_chunk_size(STREAM_MAX_CHUNK_SIZE)
            .finalize();

        assert_eq!(response.body().max_chunk_size(), STREAM_MAX_CHUNK_SIZE);
    }

    #[test]
    fn object_response_drops_hop_by_hop_headers() {
        for header in NON_REPLAYABLE_OBJECT_HEADERS {
            assert!(!is_replayable_object_header(header));
        }
        assert!(is_replayable_object_header("content-type"));
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
    !NON_REPLAYABLE_OBJECT_HEADERS
        .iter()
        .any(|header| name.eq_ignore_ascii_case(header))
}

#[async_trait]
impl<'r> FromRequest<'r> for ObjectHeaders {
    type Error = anyhow::Error;
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let md: BTreeMap<String, String> = request
            .headers()
            .iter()
            .map(|h| (h.name.into_string(), h.value.to_string()))
            .collect();
        Outcome::Success(ObjectHeaders(Metadata(md)))
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
