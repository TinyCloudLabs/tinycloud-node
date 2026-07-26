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

pub(crate) fn if_none_match_matches(value: Option<&str>, etag: &str) -> bool {
    value.is_some_and(|value| {
        value.trim() == "*" || value.split(',').any(|candidate| candidate.trim() == etag)
    })
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
    use rocket::{get, http::Header, local::asynchronous::Client, routes};
    use tinycloud_core::{hash::hash, KvBatchReadItem, KvBatchReadValue};

    #[get("/")]
    fn conditional_kv_response() -> KVResponse<Cursor<Vec<u8>>> {
        let content = b"hello".to_vec();
        KVResponse::new(
            Metadata(BTreeMap::new()),
            hash(&content),
            Cursor::new(content),
        )
    }

    #[tokio::test]
    async fn matching_kv_etag_returns_a_bodyless_304() {
        let client = Client::tracked(rocket::build().mount("/", routes![conditional_kv_response]))
            .await
            .unwrap();

        let first = client.get("/").dispatch().await;
        assert_eq!(first.status(), Status::Ok);
        let etag = first.headers().get_one("ETag").unwrap().to_string();
        assert_eq!(
            first.headers().get_one("Cache-Control"),
            Some("private, no-cache")
        );
        assert_eq!(first.into_string().await.as_deref(), Some("hello"));

        let second = client
            .get("/")
            .header(Header::new("If-None-Match", etag))
            .dispatch()
            .await;
        assert_eq!(second.status(), Status::NotModified);
        assert!(second.headers().get_one("Content-Length").is_none());
        assert!(second.into_string().await.is_none());
    }

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
            if !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("if-none-match")
            {
                r.header(Header::new(k, v));
            }
        }
        Ok(r.finalize())
    }
}

pub struct KVResponse<R>(R, pub Metadata, pub Hash);

impl<R> KVResponse<R> {
    pub fn new(md: Metadata, hash: Hash, reader: R) -> Self {
        Self(reader, md, hash)
    }
}

impl<'r, R> Responder<'r, 'static> for KVResponse<R>
where
    R: 'static + AsyncRead + Send,
{
    fn respond_to(self, r: &'r Request<'_>) -> rocket::response::Result<'static> {
        let KVResponse(content, metadata, hash) = self;
        let etag = kv_etag(hash);
        let not_modified = if_none_match_matches(r.headers().get_one("If-None-Match"), &etag);
        let mut response = Response::build_from(ObjectHeaders(metadata).respond_to(r)?);
        response.header(Header::new("ETag", etag));
        response.header(Header::new("Cache-Control", "private, no-cache"));
        if not_modified {
            response.status(Status::NotModified);
        } else {
            response
                // must ensure that Metadata::respond_to does not set the body of the response
                .streamed_body(content.compat());
        }
        Ok(response.finalize())
    }
}
