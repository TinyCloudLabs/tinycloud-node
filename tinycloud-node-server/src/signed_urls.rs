use crate::{auth_guards::if_none_match_matches, TinyCloud};
use base64::{encode_config, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use rocket::{
    futures::io::AsyncRead,
    http::{Header, Status},
    request::{FromRequest, Outcome, Request},
    response::{Responder, Response},
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_auth::resource::{Path, Service, SpaceId};
use tinycloud_core::{
    hash::Hash,
    models::{delegation, signed_kv_ticket},
    sea_orm::{ColumnTrait, EntityTrait, QueryFilter},
    storage::{ByteRangeSpec, Content, RangeRead},
    types::{Metadata, Resource},
    util::InvocationInfo,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;

type TicketIdMac = Hmac<Sha256>;

const SIGNED_KV_SERVICE: &str = "kv";
const SIGNED_KV_ABILITY: &str = "tinycloud.kv/get";
const SIGNED_KV_CACHE_CONTROL: &str = "private, no-cache";

#[derive(Debug)]
pub struct SignedUrlRuntime {
    signing_key: [u8; 32],
    max_ttl_seconds: u64,
}

impl SignedUrlRuntime {
    pub fn new(signing_key: [u8; 32]) -> Self {
        Self {
            signing_key,
            max_ttl_seconds: 300,
        }
    }

    pub fn max_ttl_seconds(&self) -> u64 {
        self.max_ttl_seconds
    }

    pub fn ticket_id(&self) -> Result<String, String> {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let mut mac = TicketIdMac::new_from_slice(&self.signing_key).map_err(|e| e.to_string())?;
        mac.update(&nonce);
        Ok(encode_config(mac.finalize().into_bytes(), URL_SAFE_NO_PAD))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedKvUrlRequest {
    pub space: String,
    pub path: String,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    #[serde(default)]
    pub max_uses: Option<u64>,
    #[serde(default)]
    pub content_hash: Option<String>,
    #[serde(default)]
    pub etag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedKvUrlResponse {
    pub url: String,
    pub ticket_id: String,
    pub expires_at: String,
}

pub struct SignedKvRangeHeader(pub ByteRangeSpec);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SignedKvRangeHeader {
    type Error = String;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one("Range") {
            Some(value) => match parse_byte_range(value) {
                Ok(range) => Outcome::Success(Self(range)),
                Err(error) => Outcome::Error((Status::BadRequest, error)),
            },
            None => Outcome::Forward(Status::NotFound),
        }
    }
}

pub struct SignedKvIfRangeHeader(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SignedKvIfRangeHeader {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one("If-Range") {
            Some(value) => Outcome::Success(Self(value.trim().to_string())),
            None => Outcome::Forward(Status::NotFound),
        }
    }
}

pub fn parse_byte_range(value: &str) -> Result<ByteRangeSpec, String> {
    let range = value
        .trim()
        .strip_prefix("bytes=")
        .ok_or_else(|| "Range must use bytes".to_string())?;
    if range.contains(',') {
        return Err("multiple byte ranges are not supported".to_string());
    }
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| "Range must contain '-'".to_string())?;
    match (start.trim(), end.trim()) {
        ("", "") => Err("Range must include a start or suffix length".to_string()),
        ("", suffix) => {
            let length = suffix
                .parse::<u64>()
                .map_err(|_| "invalid byte range suffix".to_string())?;
            if length == 0 {
                return Err("byte range suffix must be greater than zero".to_string());
            }
            Ok(ByteRangeSpec::Suffix { length })
        }
        (start, "") => Ok(ByteRangeSpec::From {
            start: start
                .parse::<u64>()
                .map_err(|_| "invalid byte range start".to_string())?,
        }),
        (start, end) => {
            let start = start
                .parse::<u64>()
                .map_err(|_| "invalid byte range start".to_string())?;
            let end = end
                .parse::<u64>()
                .map_err(|_| "invalid byte range end".to_string())?;
            if start > end {
                return Err("byte range start must not exceed end".to_string());
            }
            Ok(ByteRangeSpec::Inclusive { start, end })
        }
    }
}

pub fn if_range_allows_range(ticket_etag: Option<&str>, if_range: Option<&str>) -> bool {
    if_range.is_none_or(|if_range| ticket_etag == Some(if_range))
}

pub enum SignedKvReadResponse<R> {
    Full {
        metadata: Metadata,
        hash: Hash,
        content: Content<R>,
    },
    Partial {
        metadata: Metadata,
        hash: Hash,
        total_size: u64,
        range: tinycloud_core::storage::ResolvedByteRange,
        content: Content<R>,
    },
    Unsatisfiable {
        hash: Hash,
        total_size: u64,
    },
}

impl<R> SignedKvReadResponse<R> {
    pub fn from_range(metadata: Metadata, hash: Hash, read: RangeRead<R>) -> Self {
        match read {
            RangeRead::Content {
                total_size,
                range,
                content,
            } => Self::Partial {
                metadata,
                hash,
                total_size,
                range,
                content,
            },
            RangeRead::Unsatisfiable { total_size } => Self::Unsatisfiable { hash, total_size },
        }
    }
}

impl<'r, R> Responder<'r, 'static> for SignedKvReadResponse<R>
where
    R: 'static + AsyncRead + Send,
{
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'static> {
        let mut response = Response::build();

        match self {
            Self::Full {
                metadata,
                hash,
                content,
            } => {
                crate::prometheus::observe_signed_kv_transfer(content.len(), content.len());
                add_object_headers(&mut response, metadata);
                let etag = etag(&hash);
                response.header(Header::new("ETag", etag.clone()));
                if if_none_match_matches(request.headers().get_one("If-None-Match"), &etag) {
                    response.status(Status::NotModified);
                } else {
                    response.header(Header::new("Content-Length", content.len().to_string()));
                    response.streamed_body(content.compat());
                }
            }
            Self::Partial {
                metadata,
                hash,
                total_size,
                range,
                content,
            } => {
                crate::prometheus::observe_signed_kv_transfer(total_size, content.len());
                add_object_headers(&mut response, metadata);
                response.status(Status::PartialContent);
                let etag = etag(&hash);
                response.header(Header::new("ETag", etag.clone()));
                if if_none_match_matches(request.headers().get_one("If-None-Match"), &etag) {
                    response.status(Status::NotModified);
                } else {
                    response.header(Header::new(
                        "Content-Range",
                        format!("bytes {}-{}/{}", range.start(), range.end(), total_size),
                    ));
                    response.header(Header::new("Content-Length", content.len().to_string()));
                    response.streamed_body(content.compat());
                }
            }
            Self::Unsatisfiable { hash, total_size } => {
                response.status(Status::RangeNotSatisfiable);
                response.header(Header::new("ETag", etag(&hash)));
                response.header(Header::new(
                    "Content-Range",
                    format!("bytes */{total_size}"),
                ));
            }
        }
        response.header(Header::new("Accept-Ranges", "bytes"));
        response.header(Header::new("Cache-Control", SIGNED_KV_CACHE_CONTROL));
        Ok(response.finalize())
    }
}

fn add_object_headers(response: &mut rocket::response::Builder<'_>, metadata: Metadata) {
    for (key, value) in metadata.0 {
        if !key.eq_ignore_ascii_case("cache-control")
            && !key.eq_ignore_ascii_case("content-length")
            && !key.eq_ignore_ascii_case("content-range")
        {
            response.header(Header::new(key, value));
        }
    }
}

fn etag(hash: &Hash) -> String {
    format!("\"blake3-{}\"", hex::encode(hash.as_ref()))
}

pub async fn mint_signed_kv_url(
    invocation: &InvocationInfo,
    request: SignedKvUrlRequest,
    runtime: &SignedUrlRuntime,
    tinycloud: &TinyCloud,
) -> Result<SignedKvUrlResponse, (Status, String)> {
    if request.max_uses.is_some() {
        return Err((
            Status::BadRequest,
            "maxUses is not supported for signed KV URLs yet".to_string(),
        ));
    }

    let space: SpaceId = request
        .space
        .parse()
        .map_err(|_| (Status::BadRequest, "Invalid space ID".to_string()))?;
    let path: Path = request
        .path
        .parse()
        .map_err(|_| (Status::BadRequest, "Invalid path".to_string()))?;

    if !has_attenuable_kv_get(invocation, &space, &path)? {
        return Err((
            Status::Forbidden,
            "signed URL scope is not authorized".to_string(),
        ));
    }

    let requested_hash = request
        .content_hash
        .as_deref()
        .map(normalize_content_hash)
        .transpose()?;
    let etag_hash = request
        .etag
        .as_deref()
        .map(normalize_content_hash)
        .transpose()?;
    if let (Some(requested_hash), Some(etag_hash)) = (&requested_hash, &etag_hash) {
        if requested_hash != etag_hash {
            return Err((
                Status::BadRequest,
                "contentHash and ETag must identify the same object".to_string(),
            ));
        }
    }
    let content_hash = match requested_hash.or(etag_hash) {
        Some(hash) => hash,
        None => tinycloud
            .kv_metadata_with_hash(&space, &path)
            .await
            .map_err(|e| (Status::InternalServerError, e.to_string()))?
            .map(|(_, hash)| hex::encode(hash.as_ref()))
            .ok_or_else(|| (Status::NotFound, "Key not found".to_string()))?,
    };
    let etag = format!("\"blake3-{content_hash}\"");

    let now = OffsetDateTime::now_utc();
    let invocation_exp = invocation_expiry(invocation);
    let parent_expiry = find_parent_expiry(invocation, tinycloud).await?;
    let parent_exp = parent_expiry.unwrap_or(invocation_exp);
    let requested_ttl = request
        .ttl_seconds
        .unwrap_or(runtime.max_ttl_seconds())
        .min(runtime.max_ttl_seconds()) as i64;
    let exp = (now.unix_timestamp() + requested_ttl)
        .min(invocation_exp)
        .min(parent_exp);

    if exp <= now.unix_timestamp() {
        return Err((
            Status::Unauthorized,
            "signed URL expired immediately".to_string(),
        ));
    }

    let ticket_id = runtime
        .ticket_id()
        .map_err(|e| (Status::InternalServerError, e))?;
    let created_at = format_timestamp(now)?;
    let expires_at = format_timestamp(unix_timestamp(exp)?)?;
    let invocation_expires_at = Some(format_timestamp(unix_timestamp(invocation_exp)?)?);
    let parent_expires_at = parent_expiry
        .map(|expiry| unix_timestamp(expiry).and_then(format_timestamp))
        .transpose()?;
    let parent_cids_json = if invocation.parents.is_empty() {
        None
    } else {
        Some(
            serde_json::to_string(
                &invocation
                    .parents
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            )
            .map_err(|e| (Status::InternalServerError, e.to_string()))?,
        )
    };

    let ticket = signed_kv_ticket::Model {
        id: ticket_id.clone(),
        issuer_did: invocation.invoker.clone(),
        subject_did: invocation.invoker.clone(),
        space_id: space.to_string(),
        path: path.to_string(),
        service: SIGNED_KV_SERVICE.to_string(),
        ability: SIGNED_KV_ABILITY.to_string(),
        created_at,
        expires_at: expires_at.clone(),
        invocation_expires_at,
        parent_expires_at,
        content_hash: Some(content_hash),
        etag: Some(etag),
        parent_cids_json,
    };
    tinycloud
        .create_signed_kv_ticket(ticket)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;
    let url = format!("/signed/kv/{ticket_id}");

    Ok(SignedKvUrlResponse {
        url,
        ticket_id,
        expires_at,
    })
}

pub async fn load_signed_kv_ticket(
    tinycloud: &TinyCloud,
    ticket_id: &str,
) -> Result<signed_kv_ticket::Model, (Status, String)> {
    let ticket = tinycloud
        .find_signed_kv_ticket(ticket_id)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?
        .ok_or_else(|| {
            (
                Status::Unauthorized,
                "signed URL ticket not found".to_string(),
            )
        })?;
    validate_signed_kv_ticket(&ticket)?;
    Ok(ticket)
}

pub fn validate_signed_kv_ticket(
    ticket: &signed_kv_ticket::Model,
) -> Result<(SpaceId, Path), (Status, String)> {
    if ticket.service != SIGNED_KV_SERVICE || ticket.ability != SIGNED_KV_ABILITY {
        return Err((
            Status::Forbidden,
            "signed URL ticket has invalid scope".to_string(),
        ));
    }

    let expires_at = OffsetDateTime::parse(&ticket.expires_at, &Rfc3339).map_err(|_| {
        (
            Status::Unauthorized,
            "signed URL ticket is invalid".to_string(),
        )
    })?;
    if expires_at <= OffsetDateTime::now_utc() {
        return Err((Status::Unauthorized, "signed URL expired".to_string()));
    }

    let space = ticket.space_id.parse().map_err(|_| {
        (
            Status::Unauthorized,
            "signed URL ticket is invalid".to_string(),
        )
    })?;
    let path = ticket.path.parse().map_err(|_| {
        (
            Status::Unauthorized,
            "signed URL ticket is invalid".to_string(),
        )
    })?;
    Ok((space, path))
}

pub fn validate_signed_kv_hash_binding(
    ticket: &signed_kv_ticket::Model,
    hash: &Hash,
) -> Result<(), (Status, String)> {
    let current_hash = hex::encode(hash.as_ref());

    if let Some(bound_hash) = &ticket.content_hash {
        let bound_hash = normalize_content_hash(bound_hash)?;
        if bound_hash != current_hash {
            return Err((
                Status::PreconditionFailed,
                "signed URL content hash does not match".to_string(),
            ));
        }
    }

    if let Some(bound_etag) = &ticket.etag {
        let current_etag = format!("\"blake3-{current_hash}\"");
        if bound_etag.trim() != current_etag {
            return Err((
                Status::PreconditionFailed,
                "signed URL ETag does not match".to_string(),
            ));
        }
    }

    Ok(())
}

pub fn has_attenuable_kv_get(
    invocation: &InvocationInfo,
    space: &SpaceId,
    path: &Path,
) -> Result<bool, (Status, String)> {
    let requested = requested_kv_resource(space, path)?;
    Ok(invocation
        .capabilities
        .iter()
        .any(|capability| matches_attenuable_kv_get(capability, &requested)))
}

fn matches_attenuable_kv_get(
    capability: &tinycloud_core::util::Capability,
    requested: &Resource,
) -> bool {
    capability.ability.as_ref().as_ref() == SIGNED_KV_ABILITY
        && requested.extends(&capability.resource)
}

fn requested_kv_resource(space: &SpaceId, path: &Path) -> Result<Resource, (Status, String)> {
    Ok(Resource::TinyCloud(
        space.clone().to_resource(
            SIGNED_KV_SERVICE
                .parse::<Service>()
                .map_err(|_| (Status::InternalServerError, "Invalid service".to_string()))?,
            Some(path.clone()),
            None,
            None,
        ),
    ))
}

fn normalize_content_hash(value: &str) -> Result<String, (Status, String)> {
    let normalized = value
        .trim()
        .trim_matches('"')
        .strip_prefix("blake3-")
        .unwrap_or_else(|| value.trim().trim_matches('"'))
        .to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err((
            Status::BadRequest,
            "contentHash must be a blake3 hex digest".to_string(),
        ));
    }
    Ok(normalized)
}

fn unix_timestamp(timestamp: i64) -> Result<OffsetDateTime, (Status, String)> {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|e| (Status::InternalServerError, e.to_string()))
}

fn format_timestamp(timestamp: OffsetDateTime) -> Result<String, (Status, String)> {
    timestamp
        .format(&Rfc3339)
        .map_err(|e| (Status::InternalServerError, e.to_string()))
}

fn invocation_expiry(invocation: &InvocationInfo) -> i64 {
    invocation
        .invocation
        .payload()
        .expiration
        .as_seconds()
        .floor() as i64
}

async fn find_parent_expiry(
    invocation: &InvocationInfo,
    tinycloud: &TinyCloud,
) -> Result<Option<i64>, (Status, String)> {
    if invocation.parents.is_empty() {
        return Ok(None);
    }

    let tx = tinycloud
        .readable()
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;
    let parent_ids: Vec<Hash> = invocation
        .parents
        .iter()
        .map(|cid| Hash::from(*cid))
        .collect();
    let expiries = delegation::Entity::find()
        .filter(delegation::Column::Id.is_in(parent_ids))
        .all(&tx)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    Ok(expiries
        .into_iter()
        .filter_map(|delegation| delegation.expiry.map(|expiry| expiry.unix_timestamp()))
        .min())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use futures::io::Cursor;
    use rocket::local::asynchronous::Client;
    use std::collections::BTreeMap;
    use tempfile::TempDir;
    use tinycloud_auth::{
        authorization::{make_invocation, InvocationOptions},
        ipld_core::cid::Cid,
        multihash_codetable::{Code, MultihashDigest},
        resolver::DID_METHODS,
        resource::{ResourceId, Service},
        siwe_recap::Ability,
        ssi::{dids::DIDBuf, jwk::JWK},
    };
    use tinycloud_core::{
        hash::hash,
        keys::StaticSecret,
        models::signed_kv_ticket,
        sea_orm::{ConnectOptions, Database},
        storage::either::Either,
        storage::StorageConfig as _,
        util::InvocationInfo as CoreInvocationInfo,
    };

    use crate::storage::file_system::FileSystemConfig as NodeFileSystemConfig;

    async fn test_tinycloud() -> Result<TinyCloud> {
        let tempdir = TempDir::new()?;
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string())).await?;
        let storage = NodeFileSystemConfig::new(tempdir.path()).open().await?;
        let _persisted = tempdir.keep();
        Ok(TinyCloud::new(
            db,
            Either::B(storage),
            StaticSecret::new(vec![0u8; 32]).unwrap(),
        )
        .await?)
    }

    fn test_invocation(kv_path: &str) -> Result<(CoreInvocationInfo, SpaceId)> {
        let jwk = JWK::generate_ed25519()?;
        let mut verification_method = DID_METHODS.generate(&jwk, "key")?.to_string();
        let fragment = verification_method
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("missing verification method fragment"))?
            .1
            .to_string();
        verification_method.push('#');
        verification_method.push_str(&fragment);

        let did: DIDBuf = verification_method
            .split('#')
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing did"))?
            .parse()?;
        let space = SpaceId::new(did, "alpha".parse()?);
        let resource: ResourceId = space.clone().to_resource(
            "kv".parse::<Service>()?,
            Some(kv_path.parse::<Path>()?),
            None,
            None,
        );

        let delegation = Cid::new_v1(0x55, Code::Blake3_256.digest(b"delegation"));
        let invocation = make_invocation(
            vec![(resource, vec!["tinycloud.kv/get".parse::<Ability>()?])],
            &delegation,
            &jwk,
            &verification_method,
            4_102_444_800.0,
            InvocationOptions::default(),
        )?;

        Ok((CoreInvocationInfo::try_from(invocation)?, space))
    }

    fn test_invocation_with_caps(
        caps: &[(&str, &str, &str)],
    ) -> Result<(CoreInvocationInfo, SpaceId)> {
        let jwk = JWK::generate_ed25519()?;
        let mut verification_method = DID_METHODS.generate(&jwk, "key")?.to_string();
        let fragment = verification_method
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("missing verification method fragment"))?
            .1
            .to_string();
        verification_method.push('#');
        verification_method.push_str(&fragment);

        let did: DIDBuf = verification_method
            .split('#')
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing did"))?
            .parse()?;
        let space = SpaceId::new(did, "alpha".parse()?);
        let resources = caps
            .iter()
            .map(|(service, path, ability)| {
                Ok((
                    space.clone().to_resource(
                        service.parse::<Service>()?,
                        Some(path.parse::<Path>()?),
                        None,
                        None,
                    ),
                    vec![ability.parse::<Ability>()?],
                ))
            })
            .collect::<Result<Vec<(ResourceId, Vec<Ability>)>>>()?;

        let delegation = Cid::new_v1(0x55, Code::Blake3_256.digest(b"delegation"));
        let invocation = make_invocation(
            resources,
            &delegation,
            &jwk,
            &verification_method,
            4_102_444_800.0,
            InvocationOptions::default(),
        )?;

        Ok((CoreInvocationInfo::try_from(invocation)?, space))
    }

    fn ticket_model(
        space: &SpaceId,
        path: &str,
        expires_at: OffsetDateTime,
    ) -> signed_kv_ticket::Model {
        signed_kv_ticket::Model {
            id: "ticket-id".to_string(),
            issuer_did: "did:key:test".to_string(),
            subject_did: "did:key:test".to_string(),
            space_id: space.to_string(),
            path: path.to_string(),
            service: SIGNED_KV_SERVICE.to_string(),
            ability: SIGNED_KV_ABILITY.to_string(),
            created_at: format_timestamp(OffsetDateTime::now_utc()).unwrap(),
            expires_at: format_timestamp(expires_at).unwrap(),
            invocation_expires_at: None,
            parent_expires_at: None,
            content_hash: None,
            etag: None,
            parent_cids_json: None,
        }
    }

    #[get("/partial")]
    fn partial_response() -> SignedKvReadResponse<Cursor<Vec<u8>>> {
        let bytes = b"world".to_vec();
        SignedKvReadResponse::Partial {
            metadata: Metadata(
                [("content-type".to_string(), "audio/wav".to_string())]
                    .into_iter()
                    .collect(),
            ),
            hash: hash(b"hello world"),
            total_size: 11,
            range: ByteRangeSpec::Inclusive { start: 6, end: 10 }
                .resolve(11)
                .unwrap(),
            content: Content::new(bytes.len() as u64, Cursor::new(bytes)),
        }
    }

    #[get("/full")]
    fn full_response() -> SignedKvReadResponse<Cursor<Vec<u8>>> {
        let bytes = b"hello".to_vec();
        SignedKvReadResponse::Full {
            metadata: Metadata(BTreeMap::new()),
            hash: hash(&bytes),
            content: Content::new(bytes.len() as u64, Cursor::new(bytes)),
        }
    }

    #[get("/hostile-metadata")]
    fn hostile_metadata_response() -> SignedKvReadResponse<Cursor<Vec<u8>>> {
        let bytes = b"hello".to_vec();
        SignedKvReadResponse::Full {
            metadata: Metadata(BTreeMap::from([
                (
                    "Cache-Control".to_string(),
                    "public, max-age=31536000".to_string(),
                ),
                ("Accept-Ranges".to_string(), "none".to_string()),
                ("Content-Range".to_string(), "bytes 0-0/1".to_string()),
            ])),
            hash: hash(&bytes),
            content: Content::new(bytes.len() as u64, Cursor::new(bytes)),
        }
    }

    #[get("/unsatisfiable")]
    fn unsatisfiable_response() -> SignedKvReadResponse<Cursor<Vec<u8>>> {
        SignedKvReadResponse::Unsatisfiable {
            hash: hash(b"hello"),
            total_size: 5,
        }
    }

    #[test]
    fn parses_single_http_byte_ranges() {
        assert_eq!(
            parse_byte_range("bytes=10-19").unwrap(),
            ByteRangeSpec::Inclusive { start: 10, end: 19 }
        );
        assert_eq!(
            parse_byte_range("bytes=10-").unwrap(),
            ByteRangeSpec::From { start: 10 }
        );
        assert_eq!(
            parse_byte_range("bytes=-10").unwrap(),
            ByteRangeSpec::Suffix { length: 10 }
        );
        assert!(parse_byte_range("bytes=0-1,4-5").is_err());
        assert!(parse_byte_range("items=0-1").is_err());
        assert!(parse_byte_range("bytes=20-10").is_err());
    }

    #[test]
    fn if_range_requires_the_bound_etag() {
        let etag = "\"blake3-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"";
        assert!(if_range_allows_range(Some(etag), None));
        assert!(if_range_allows_range(Some(etag), Some(etag)));
        assert!(!if_range_allows_range(Some(etag), Some("\"other\"")));
        assert!(!if_range_allows_range(None, Some(etag)));
    }

    #[tokio::test]
    async fn partial_response_has_range_etag_and_exact_body_length() -> Result<()> {
        let client = Client::tracked(rocket::build().mount("/", routes![partial_response])).await?;
        let response = client.get("/partial").dispatch().await;
        assert_eq!(response.status(), Status::PartialContent);
        assert_eq!(
            response.headers().get_one("Cache-Control"),
            Some(SIGNED_KV_CACHE_CONTROL)
        );
        assert_eq!(response.headers().get_one("Accept-Ranges"), Some("bytes"));
        assert_eq!(
            response.headers().get_one("Content-Range"),
            Some("bytes 6-10/11")
        );
        assert_eq!(response.headers().get_one("Content-Length"), Some("5"));
        assert_eq!(
            response.headers().get_one("Content-Type"),
            Some("audio/wav")
        );
        assert_eq!(
            response.headers().get_one("ETag"),
            Some(etag(&hash(b"hello world")).as_str())
        );
        assert_eq!(response.into_bytes().await.unwrap(), b"world");
        Ok(())
    }

    #[tokio::test]
    async fn signed_kv_responses_are_never_publicly_cacheable() -> Result<()> {
        let client = Client::tracked(rocket::build().mount(
            "/",
            routes![full_response, partial_response, unsatisfiable_response],
        ))
        .await?;

        for path in ["/full", "/partial", "/unsatisfiable"] {
            let response = client.get(path).dispatch().await;
            let cache_control = response.headers().get_one("Cache-Control");
            assert_eq!(cache_control, Some(SIGNED_KV_CACHE_CONTROL), "{path}");
            assert!(!cache_control.is_some_and(|value| value.contains("public")));
        }
        Ok(())
    }

    #[tokio::test]
    async fn signed_kv_policy_headers_override_stored_metadata() -> Result<()> {
        let client =
            Client::tracked(rocket::build().mount("/", routes![hostile_metadata_response])).await?;

        let response = client.get("/hostile-metadata").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.headers().get_one("Cache-Control"),
            Some(SIGNED_KV_CACHE_CONTROL)
        );
        assert_eq!(response.headers().get_one("Accept-Ranges"), Some("bytes"));
        assert!(response.headers().get_one("Content-Range").is_none());
        assert_eq!(response.into_bytes().await.unwrap(), b"hello");
        Ok(())
    }

    #[tokio::test]
    async fn signed_kv_ticket_rejects_expired_ticket() -> Result<()> {
        let (_invocation, space) = test_invocation("documents/audio.wav")?;
        let ticket = ticket_model(
            &space,
            "documents/audio.wav",
            OffsetDateTime::now_utc() - time::Duration::seconds(1),
        );

        let err =
            validate_signed_kv_ticket(&ticket).expect_err("expired ticket should be rejected");
        assert_eq!(err.0, Status::Unauthorized);
        Ok(())
    }

    #[tokio::test]
    async fn mints_signed_kv_url_for_authorized_exact_scope() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let runtime = SignedUrlRuntime::new([7u8; 32]);
        let (invocation, space) = test_invocation("documents/audio.wav")?;
        let response = mint_signed_kv_url(
            &invocation,
            SignedKvUrlRequest {
                space: space.to_string(),
                path: "documents/audio.wav".to_string(),
                ttl_seconds: Some(60),
                max_uses: None,
                content_hash: Some(hex::encode(hash(b"object bytes").as_ref())),
                etag: None,
            },
            &runtime,
            &tinycloud,
        )
        .await
        .expect("signed URL");

        assert_eq!(response.url, format!("/signed/kv/{}", response.ticket_id));
        assert!(!response.url.contains("?token="));
        assert!(!response.url.contains(&space.to_string()));

        let ticket = load_signed_kv_ticket(&tinycloud, &response.ticket_id)
            .await
            .expect("minted ticket should be persisted");
        let (ticket_space, ticket_path) =
            validate_signed_kv_ticket(&ticket).expect("persisted ticket should validate");
        assert_eq!(ticket_space, space);
        assert_eq!(ticket_path.as_str(), "documents/audio.wav");
        let expected_hash = hex::encode(hash(b"object bytes").as_ref());
        assert_eq!(ticket.content_hash.as_deref(), Some(expected_hash.as_str()));
        assert_eq!(
            ticket.etag.as_deref(),
            Some(format!("\"blake3-{expected_hash}\"").as_str())
        );
        Ok(())
    }

    #[tokio::test]
    async fn mints_signed_kv_url_for_broader_kv_get_among_other_caps() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let runtime = SignedUrlRuntime::new([7u8; 32]);
        let (invocation, space) = test_invocation_with_caps(&[
            ("kv", "documents", "tinycloud.kv/get"),
            ("sql", "main.db", "tinycloud.sql/read"),
        ])?;
        let response = mint_signed_kv_url(
            &invocation,
            SignedKvUrlRequest {
                space: space.to_string(),
                path: "documents/audio.wav".to_string(),
                ttl_seconds: Some(60),
                max_uses: None,
                content_hash: Some(hex::encode(hash(b"object bytes").as_ref())),
                etag: None,
            },
            &runtime,
            &tinycloud,
        )
        .await
        .expect("broader kv/get capability should authorize ticket");

        assert_eq!(response.url, format!("/signed/kv/{}", response.ticket_id));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_unauthorized_path_scope() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let runtime = SignedUrlRuntime::new([7u8; 32]);
        let (invocation, space) = test_invocation_with_caps(&[
            ("kv", "documents", "tinycloud.kv/get"),
            ("kv", "other", "tinycloud.kv/put"),
        ])?;

        let err = mint_signed_kv_url(
            &invocation,
            SignedKvUrlRequest {
                space: space.to_string(),
                path: "documents2/audio.wav".to_string(),
                ttl_seconds: Some(60),
                max_uses: None,
                content_hash: None,
                etag: None,
            },
            &runtime,
            &tinycloud,
        )
        .await
        .expect_err("sibling path should not be authorized by prefix");

        assert_eq!(err.0, Status::Forbidden);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_max_uses_without_durable_state() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let runtime = SignedUrlRuntime::new([7u8; 32]);
        let (invocation, space) = test_invocation("documents/audio.wav")?;

        let err = mint_signed_kv_url(
            &invocation,
            SignedKvUrlRequest {
                space: space.to_string(),
                path: "documents/audio.wav".to_string(),
                ttl_seconds: Some(60),
                max_uses: Some(1),
                content_hash: None,
                etag: None,
            },
            &runtime,
            &tinycloud,
        )
        .await
        .expect_err("maxUses should be rejected");

        assert_eq!(err.0, Status::BadRequest);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_mismatched_content_hash_and_etag() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let runtime = SignedUrlRuntime::new([7u8; 32]);
        let (invocation, space) = test_invocation("documents/audio.wav")?;

        let err = mint_signed_kv_url(
            &invocation,
            SignedKvUrlRequest {
                space: space.to_string(),
                path: "documents/audio.wav".to_string(),
                ttl_seconds: Some(60),
                max_uses: None,
                content_hash: Some(hex::encode(hash(b"object bytes").as_ref())),
                etag: Some(format!(
                    "\"blake3-{}\"",
                    hex::encode(hash(b"other").as_ref())
                )),
            },
            &runtime,
            &tinycloud,
        )
        .await
        .expect_err("mismatched object bindings must be rejected");

        assert_eq!(err.0, Status::BadRequest);
        Ok(())
    }

    #[tokio::test]
    async fn authorization_allows_attenuable_kv_get_scope() -> Result<()> {
        let (invocation, space) = test_invocation_with_caps(&[
            ("kv", "documents", "tinycloud.kv/get"),
            ("kv", "uploads", "tinycloud.kv/put"),
        ])?;
        let authorized_path = "documents/audio.wav".parse::<Path>()?;
        let wrong_path = "documents2/audio.wav".parse::<Path>()?;

        assert!(has_attenuable_kv_get(&invocation, &space, &authorized_path)
            .expect("valid requested resource"));
        assert!(!has_attenuable_kv_get(&invocation, &space, &wrong_path)
            .expect("valid requested resource"));
        Ok(())
    }

    #[tokio::test]
    async fn validates_optional_content_hash_binding() -> Result<()> {
        let (_invocation, space) = test_invocation("documents/audio.wav")?;
        let object_hash = hash(b"object bytes");
        let mut ticket = ticket_model(
            &space,
            "documents/audio.wav",
            OffsetDateTime::now_utc() + time::Duration::seconds(60),
        );
        ticket.content_hash = Some(hex::encode(object_hash.as_ref()));
        validate_signed_kv_hash_binding(&ticket, &object_hash)
            .expect("matching content hash should validate");

        let other_hash = hash(b"other bytes");
        let err = validate_signed_kv_hash_binding(&ticket, &other_hash)
            .expect_err("mismatched content hash should be rejected");
        assert_eq!(err.0, Status::PreconditionFailed);
        Ok(())
    }
}
