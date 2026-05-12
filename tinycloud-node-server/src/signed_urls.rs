use crate::TinyCloud;
use base64::{encode_config, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use rocket::http::Status;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_auth::resource::{Path, Service, SpaceId};
use tinycloud_core::{
    hash::Hash,
    models::{delegation, signed_kv_ticket},
    sea_orm::{ColumnTrait, EntityTrait, QueryFilter},
    types::Resource,
    util::InvocationInfo,
};

type TicketIdMac = Hmac<Sha256>;

const SIGNED_KV_SERVICE: &str = "kv";
const SIGNED_KV_ABILITY: &str = "tinycloud.kv/get";

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
    let content_hash = request
        .content_hash
        .as_deref()
        .map(normalize_content_hash)
        .transpose()?;
    let etag = request.etag.map(|etag| etag.trim().to_string());
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
        content_hash,
        etag,
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
                content_hash: None,
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
                content_hash: None,
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
