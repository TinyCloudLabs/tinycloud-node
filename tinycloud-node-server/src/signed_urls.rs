use crate::TinyCloud;
use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rocket::http::Status;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_auth::resource::{Path, SpaceId};
use tinycloud_core::{
    hash::Hash,
    models::delegation,
    sea_orm::{ColumnTrait, EntityTrait, QueryFilter},
    types::Resource,
    util::InvocationInfo,
};

type SignedUrlMac = Hmac<Sha256>;

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

    pub fn sign(&self, claims: &SignedKvUrlClaims) -> Result<String, String> {
        let payload = serde_json::to_vec(claims).map_err(|e| e.to_string())?;
        let encoded_payload = encode_config(payload, URL_SAFE_NO_PAD);
        let mut mac = SignedUrlMac::new_from_slice(&self.signing_key).map_err(|e| e.to_string())?;
        mac.update(encoded_payload.as_bytes());
        let signature = mac.finalize().into_bytes();
        let encoded_signature = encode_config(signature, URL_SAFE_NO_PAD);
        Ok(format!("{encoded_payload}.{encoded_signature}"))
    }

    pub fn verify(&self, token: &str) -> Result<SignedKvUrlClaims, String> {
        let (encoded_payload, encoded_signature) = token
            .split_once('.')
            .ok_or_else(|| "invalid signed URL token format".to_string())?;

        let mut mac = SignedUrlMac::new_from_slice(&self.signing_key).map_err(|e| e.to_string())?;
        mac.update(encoded_payload.as_bytes());
        let signature = decode_config(encoded_signature, URL_SAFE_NO_PAD)
            .map_err(|_| "invalid signed URL token signature".to_string())?;
        mac.verify_slice(&signature)
            .map_err(|_| "invalid signed URL token signature".to_string())?;

        let payload = decode_config(encoded_payload, URL_SAFE_NO_PAD)
            .map_err(|_| "invalid signed URL token payload".to_string())?;
        serde_json::from_slice(&payload).map_err(|_| "invalid signed URL token payload".to_string())
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedKvUrlResponse {
    pub url: String,
    pub token: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedKvUrlClaims {
    pub v: u8,
    pub sub: String,
    pub space: String,
    pub path: String,
    pub iat: i64,
    pub exp: i64,
    pub parent_exp: i64,
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

    if !has_only_exact_kv_get(invocation, &space, &path) {
        return Err((
            Status::Forbidden,
            "signed URL scope is not authorized".to_string(),
        ));
    }

    let now = OffsetDateTime::now_utc();
    let invocation_exp = invocation_expiry(invocation);
    let parent_exp = find_parent_expiry(invocation, tinycloud)
        .await?
        .unwrap_or(invocation_exp);
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

    let claims = SignedKvUrlClaims {
        v: 1,
        sub: invocation.invoker.clone(),
        space: space.to_string(),
        path: path.to_string(),
        iat: now.unix_timestamp(),
        exp,
        parent_exp,
    };
    let token = runtime
        .sign(&claims)
        .map_err(|e| (Status::InternalServerError, e))?;
    let expires_at = OffsetDateTime::from_unix_timestamp(exp)
        .map_err(|e| (Status::InternalServerError, e.to_string()))?
        .format(&Rfc3339)
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;
    let url = format!("/signed/kv/{}/{}?token={}", space, path, token);

    Ok(SignedKvUrlResponse {
        url,
        token,
        expires_at,
    })
}

pub fn validate_signed_kv_url(
    runtime: &SignedUrlRuntime,
    token: &str,
    space: &SpaceId,
    path: &Path,
) -> Result<SignedKvUrlClaims, (Status, String)> {
    let claims = runtime
        .verify(token)
        .map_err(|e| (Status::Unauthorized, e))?;
    let now = OffsetDateTime::now_utc().unix_timestamp();

    if claims.exp <= now || claims.parent_exp <= now {
        return Err((Status::Unauthorized, "signed URL expired".to_string()));
    }
    if claims.space != space.to_string() || claims.path != path.to_string() {
        return Err((
            Status::Forbidden,
            "signed URL scope does not match request".to_string(),
        ));
    }

    Ok(claims)
}

pub fn has_only_exact_kv_get(invocation: &InvocationInfo, space: &SpaceId, path: &Path) -> bool {
    !invocation.capabilities.is_empty()
        && invocation
            .capabilities
            .iter()
            .all(|capability| matches_exact_kv_get(capability, space, path))
}

fn matches_exact_kv_get(
    capability: &tinycloud_core::util::Capability,
    space: &SpaceId,
    path: &Path,
) -> bool {
    match (&capability.resource, capability.ability.as_ref().as_ref()) {
        (Resource::TinyCloud(resource), "tinycloud.kv/get") => {
            resource.service().as_str() == "kv"
                && resource.space() == space
                && resource.path().is_some_and(|p| p == path)
        }
        _ => false,
    }
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
        keys::StaticSecret,
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

    #[tokio::test]
    async fn signed_kv_url_token_round_trips() {
        let runtime = SignedUrlRuntime::new([7u8; 32]);
        let claims = SignedKvUrlClaims {
            v: 1,
            sub: "did:key:test".to_string(),
            space: "tinycloud:space".to_string(),
            path: "documents/audio.wav".to_string(),
            iat: 10,
            exp: 20,
            parent_exp: 20,
        };

        let token = runtime.sign(&claims).unwrap();
        let decoded = runtime.verify(&token).unwrap();
        assert_eq!(decoded, claims);
    }

    #[tokio::test]
    async fn signed_kv_url_rejects_wrong_path_scope() -> Result<()> {
        let runtime = SignedUrlRuntime::new([7u8; 32]);
        let (invocation, space) = test_invocation("documents/audio.wav")?;
        let claims = SignedKvUrlClaims {
            v: 1,
            sub: invocation.invoker,
            space: space.to_string(),
            path: "documents/audio.wav".to_string(),
            iat: 10,
            exp: 4_102_444_800,
            parent_exp: 4_102_444_800,
        };
        let token = runtime.sign(&claims).unwrap();
        let wrong_path = "documents/other.wav".parse::<Path>()?;

        let err = validate_signed_kv_url(&runtime, &token, &space, &wrong_path)
            .expect_err("wrong path should be rejected");
        assert_eq!(err.0, Status::Forbidden);
        Ok(())
    }

    #[tokio::test]
    async fn signed_kv_url_rejects_expired_token() -> Result<()> {
        let runtime = SignedUrlRuntime::new([7u8; 32]);
        let (_invocation, space) = test_invocation("documents/audio.wav")?;
        let path = "documents/audio.wav".parse::<Path>()?;
        let claims = SignedKvUrlClaims {
            v: 1,
            sub: "did:key:test".to_string(),
            space: space.to_string(),
            path: path.to_string(),
            iat: 10,
            exp: 20,
            parent_exp: 20,
        };
        let token = runtime.sign(&claims).unwrap();

        let err = validate_signed_kv_url(&runtime, &token, &space, &path)
            .expect_err("expired token should be rejected");
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
            },
            &runtime,
            &tinycloud,
        )
        .await
        .expect("signed URL");

        let path = "documents/audio.wav".parse::<Path>()?;
        let claims = validate_signed_kv_url(&runtime, &response.token, &space, &path)
            .expect("minted URL should validate");
        assert_eq!(claims.space, space.to_string());
        assert_eq!(claims.path, "documents/audio.wav");
        assert!(response.url.starts_with("/signed/kv/"));
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
    async fn authorization_requires_exact_kv_get_scope() -> Result<()> {
        let (invocation, space) = test_invocation("documents/audio.wav")?;
        let authorized_path = "documents/audio.wav".parse::<Path>()?;
        let wrong_path = "documents/other.wav".parse::<Path>()?;

        assert!(has_only_exact_kv_get(&invocation, &space, &authorized_path));
        assert!(!has_only_exact_kv_get(&invocation, &space, &wrong_path));
        Ok(())
    }
}
