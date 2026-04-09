use crate::{
    authorization::AuthHeaderGetter,
    hooks::{
        hook_scope_path, matches_scope, normalize_path_prefix, HookRuntime, HookSubscription,
        HookTicketClaims, HookTicketRequest, HookTicketResponse,
    },
    TinyCloud,
};
use rocket::{
    delete,
    form::FromForm,
    get,
    http::Status,
    post,
    response::stream::{Event, EventStream},
    serde::json::Json,
    State,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_core::{
    hash::Blake3Hasher,
    hash::Hash,
    models::{delegation, hook_subscription},
    sea_orm::{ColumnTrait, EntityTrait, QueryFilter},
    types::Resource,
    util::InvocationInfo,
    ColumnEncryption,
};

#[post("/hooks/tickets", format = "json", data = "<request>")]
pub async fn create_hook_ticket(
    invocation: AuthHeaderGetter<InvocationInfo>,
    request: Json<HookTicketRequest>,
    hooks: &State<HookRuntime>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<HookTicketResponse>, (Status, String)> {
    mint_hook_ticket(
        &invocation.0 .0,
        request.into_inner(),
        hooks.inner(),
        tinycloud.inner(),
    )
    .await
    .map(Json)
}

pub async fn mint_hook_ticket(
    invocation: &InvocationInfo,
    mut request: HookTicketRequest,
    hooks: &HookRuntime,
    tinycloud: &TinyCloud,
) -> Result<HookTicketResponse, (Status, String)> {
    if request.subscriptions.is_empty() {
        return Err((
            Status::BadRequest,
            "at least one subscription is required".to_string(),
        ));
    }
    if request.subscriptions.len() > hooks.config().max_scopes_per_ticket {
        return Err((
            Status::BadRequest,
            "too many requested hook scopes".to_string(),
        ));
    }

    for subscription in &mut request.subscriptions {
        subscription.path_prefix = normalize_path_prefix(subscription.path_prefix.take());
        validate_subscription(subscription)?;
        if !is_subscription_authorized(invocation, subscription) {
            return Err((
                Status::Forbidden,
                "requested hook scope is not authorized".to_string(),
            ));
        }
    }

    let now = OffsetDateTime::now_utc();
    let invocation_exp = invocation_expiry(invocation)?;
    let parent_exp = find_parent_expiry(invocation, tinycloud)
        .await?
        .unwrap_or(invocation_exp);
    let requested_ttl = request
        .ttl_seconds
        .unwrap_or(hooks.config().max_ticket_ttl_seconds)
        .min(hooks.config().max_ticket_ttl_seconds) as i64;

    let exp = (now.unix_timestamp() + requested_ttl)
        .min(invocation_exp)
        .min(parent_exp);

    if exp <= now.unix_timestamp() {
        return Err((
            Status::Unauthorized,
            "hook ticket expired immediately".to_string(),
        ));
    }

    let claims = HookTicketClaims {
        v: 1,
        sub: invocation.invoker.clone(),
        scopes: request.subscriptions,
        iat: now.unix_timestamp(),
        exp,
        parent_exp,
    };
    let ticket = hooks
        .sign_ticket(&claims)
        .map_err(|e| (Status::InternalServerError, e))?;
    let expires_at = OffsetDateTime::from_unix_timestamp(exp)
        .map_err(|e| (Status::InternalServerError, e.to_string()))?
        .format(&Rfc3339)
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    Ok(HookTicketResponse { ticket, expires_at })
}

#[get("/hooks/events?<ticket>")]
pub async fn hook_events<'r>(
    ticket: &'r str,
    hooks: &'r State<HookRuntime>,
) -> Result<EventStream![Event + 'r], (Status, String)> {
    let claims = hooks
        .verify_ticket(ticket)
        .map_err(|e| (Status::Unauthorized, e))?;
    let lease = hooks
        .try_acquire_stream()
        .map_err(|e| (Status::TooManyRequests, e))?;

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let deadline = claims
        .exp
        .min(claims.parent_exp)
        .min(now + hooks.config().max_ticket_ttl_seconds as i64);

    if deadline <= now {
        return Err((Status::Unauthorized, "hook ticket expired".to_string()));
    }

    let mut receiver = hooks.bus().subscribe();
    let sleep_duration = Duration::from_secs((deadline - now) as u64);

    Ok(EventStream! {
        let _lease = lease;
        let deadline_sleep = rocket::tokio::time::sleep(sleep_duration);
        rocket::tokio::pin!(deadline_sleep);

        loop {
            rocket::tokio::select! {
                _ = &mut deadline_sleep => {
                    break;
                }
                message = receiver.recv() => {
                    match message {
                        Ok(event) => {
                            if claims.scopes.iter().any(|scope| matches_scope(&event, scope)) {
                                yield Event::json(&event)
                                    .id(event.id.clone())
                                    .event("write");
                            }
                        }
                        Err(rocket::tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            continue;
                        }
                        Err(rocket::tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            }
        }
    }
    .heartbeat(Duration::from_secs(30)))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HookWebhookRequest {
    pub space: String,
    pub service: String,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub abilities: Vec<String>,
    pub callback_url: String,
    pub secret: String,
}

#[derive(Debug, Clone, FromForm)]
pub struct HookWebhookListQuery {
    pub space: String,
    pub service: String,
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookWebhookResponse {
    pub id: String,
    pub subscriber_did: String,
    pub space: String,
    pub service: String,
    pub path_prefix: Option<String>,
    pub abilities: Vec<String>,
    pub callback_url: String,
    pub secret_key_id: String,
    pub active: bool,
    pub created_at: String,
}

pub const HOOK_WEBHOOK_SECRET_KEY_ID: &str = "primary";

#[post("/hooks/webhooks", format = "json", data = "<request>")]
pub async fn create_webhook(
    invocation: AuthHeaderGetter<InvocationInfo>,
    request: Json<HookWebhookRequest>,
    hooks: &State<HookRuntime>,
    tinycloud: &State<TinyCloud>,
    webhook_encryption: &State<ColumnEncryption>,
) -> Result<Json<HookWebhookResponse>, (Status, String)> {
    let normalized = normalize_webhook_request(&request)?;
    if !is_hook_action_authorized(&invocation.0 .0, &normalized, "tinycloud.hooks/register") {
        return Err((
            Status::Forbidden,
            "webhook scope is not authorized".to_string(),
        ));
    }

    let active_count = tinycloud
        .count_active_hook_subscriptions(&normalized.space)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;
    if active_count >= hooks.config().max_webhook_subscriptions_per_space as u64 {
        return Err((
            Status::TooManyRequests,
            "webhook subscription limit reached for space".to_string(),
        ));
    }

    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("current timestamps should format as RFC3339");
    let model = hook_subscription::Model {
        id: hook_subscription_id(
            &invocation.0 .0.invoker,
            &normalized,
            &request.callback_url,
            &created_at,
        ),
        subscriber_did: invocation.0 .0.invoker.clone(),
        space_id: normalized.space.clone(),
        target_service: normalized.service.clone(),
        path_prefix: normalized.path_prefix.clone(),
        abilities_json: hook_subscription::Model::set_abilities(&normalized.abilities),
        callback_url: request.callback_url.clone(),
        encrypted_secret: webhook_encryption.encrypt(request.secret.as_bytes()),
        secret_key_id: HOOK_WEBHOOK_SECRET_KEY_ID.to_string(),
        active: true,
        created_at,
    };

    let saved = tinycloud
        .create_hook_subscription(model)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    webhook_response_from_model(&saved).map(Json)
}

#[get("/hooks/webhooks?<query..>")]
pub async fn list_webhooks(
    invocation: AuthHeaderGetter<InvocationInfo>,
    query: HookWebhookListQuery,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<Vec<HookWebhookResponse>>, (Status, String)> {
    let normalized_prefix = normalize_path_prefix(query.prefix.clone());
    let requested_scope = HookSubscription {
        space: query.space.clone(),
        service: query.service.clone(),
        path_prefix: normalized_prefix.clone(),
        abilities: Vec::new(),
    };

    validate_subscription(&requested_scope)?;
    if !is_hook_action_authorized(&invocation.0 .0, &requested_scope, "tinycloud.hooks/list") {
        return Err((
            Status::Forbidden,
            "webhook scope is not authorized".to_string(),
        ));
    }

    let rows = tinycloud
        .list_active_hook_subscriptions(
            &requested_scope.space,
            &requested_scope.service,
            normalized_prefix.as_deref(),
        )
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    rows.into_iter()
        .map(|row| webhook_response_from_model(&row))
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

#[delete("/hooks/webhooks/<subscription_id>")]
pub async fn delete_webhook(
    invocation: AuthHeaderGetter<InvocationInfo>,
    subscription_id: &str,
    tinycloud: &State<TinyCloud>,
) -> Result<Status, (Status, String)> {
    let Some(subscription) = tinycloud
        .find_hook_subscription(subscription_id)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?
    else {
        return Err((
            Status::NotFound,
            "webhook subscription not found".to_string(),
        ));
    };

    let requested_scope = HookSubscription {
        space: subscription.space_id.clone(),
        service: subscription.target_service.clone(),
        path_prefix: subscription.path_prefix.clone(),
        abilities: subscription
            .abilities()
            .map_err(|e| (Status::InternalServerError, e.to_string()))?,
    };
    if !is_hook_action_authorized(
        &invocation.0 .0,
        &requested_scope,
        "tinycloud.hooks/unregister",
    ) {
        return Err((
            Status::Forbidden,
            "webhook scope is not authorized".to_string(),
        ));
    }

    tinycloud
        .deactivate_hook_subscription(subscription_id)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;
    Ok(Status::NoContent)
}

fn validate_subscription(subscription: &HookSubscription) -> Result<(), (Status, String)> {
    if !matches!(subscription.service.as_str(), "kv" | "sql" | "duckdb") {
        return Err((Status::BadRequest, "Unsupported hook service".to_string()));
    }

    let allowed_abilities: &[&str] = match subscription.service.as_str() {
        "kv" => &["tinycloud.kv/put", "tinycloud.kv/del"],
        "sql" => &["tinycloud.sql/write"],
        "duckdb" => &["tinycloud.duckdb/write"],
        _ => unreachable!(),
    };

    if subscription
        .abilities
        .iter()
        .any(|ability| !allowed_abilities.contains(&ability.as_str()))
    {
        return Err((
            Status::BadRequest,
            "hook ability filter does not match service".to_string(),
        ));
    }

    Ok(())
}

fn is_subscription_authorized(
    invocation: &InvocationInfo,
    subscription: &HookSubscription,
) -> bool {
    is_hook_action_authorized(invocation, subscription, "tinycloud.hooks/subscribe")
}

fn is_hook_action_authorized(
    invocation: &InvocationInfo,
    subscription: &HookSubscription,
    ability: &str,
) -> bool {
    let requested_scope =
        hook_scope_path(&subscription.service, subscription.path_prefix.as_deref());

    invocation.capabilities.iter().any(|capability| {
        match (&capability.resource, capability.ability.as_ref().as_ref()) {
            (Resource::TinyCloud(resource), requested_ability)
                if requested_ability == ability
                    && resource.service().as_str() == "hooks"
                    && resource.space().to_string() == subscription.space =>
            {
                match resource.path() {
                    Some(path) => scope_extends(&requested_scope, &path.to_string()),
                    None => true,
                }
            }
            _ => false,
        }
    })
}

fn scope_extends(requested_scope: &str, authorized_scope: &str) -> bool {
    requested_scope == authorized_scope
        || requested_scope.starts_with(&format!("{authorized_scope}/"))
}

fn invocation_expiry(invocation: &InvocationInfo) -> Result<i64, (Status, String)> {
    Ok(invocation
        .invocation
        .payload()
        .expiration
        .as_seconds()
        .floor() as i64)
}

pub fn normalize_webhook_request(
    request: &HookWebhookRequest,
) -> Result<HookSubscription, (Status, String)> {
    let path_prefix = normalize_path_prefix(request.path_prefix.clone());
    let subscription = HookSubscription {
        space: request.space.clone(),
        service: request.service.clone(),
        path_prefix,
        abilities: request.abilities.clone(),
    };

    validate_subscription(&subscription)?;

    if request.callback_url.trim().is_empty() {
        return Err((Status::BadRequest, "callbackUrl is required".to_string()));
    }
    if request.secret.is_empty() {
        return Err((Status::BadRequest, "secret is required".to_string()));
    }

    reqwest::Url::parse(&request.callback_url)
        .map_err(|e| (Status::BadRequest, format!("invalid callbackUrl: {e}")))?;

    Ok(subscription)
}

pub fn webhook_response_from_model(
    model: &hook_subscription::Model,
) -> Result<HookWebhookResponse, (Status, String)> {
    let abilities = model
        .abilities()
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    Ok(HookWebhookResponse {
        id: model.id.clone(),
        subscriber_did: model.subscriber_did.clone(),
        space: model.space_id.clone(),
        service: model.target_service.clone(),
        path_prefix: model.path_prefix.clone(),
        abilities,
        callback_url: model.callback_url.clone(),
        secret_key_id: model.secret_key_id.clone(),
        active: model.active,
        created_at: model.created_at.clone(),
    })
}

fn hook_subscription_id(
    subscriber_did: &str,
    subscription: &HookSubscription,
    callback_url: &str,
    created_at: &str,
) -> String {
    let mut hasher = Blake3Hasher::new();
    hasher.update(subscriber_did.as_bytes());
    hasher.update(b":");
    hasher.update(subscription.space.as_bytes());
    hasher.update(b":");
    hasher.update(subscription.service.as_bytes());
    hasher.update(b":");
    hasher.update(
        subscription
            .path_prefix
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update(b":");
    hasher.update(callback_url.as_bytes());
    hasher.update(b":");
    hasher.update(created_at.as_bytes());
    hasher.finalize().to_cid(0x55).to_string()
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
    use crate::{
        config::HooksConfig, hooks::HookRuntime,
        storage::file_system::FileSystemConfig as NodeFileSystemConfig, TinyCloud,
    };
    use anyhow::Result;
    use rocket::http::Status;
    use tempfile::TempDir;
    use tinycloud_auth::{
        authorization::{make_invocation, InvocationOptions},
        ipld_core::cid::Cid,
        multihash_codetable::{Code, MultihashDigest},
        resolver::DID_METHODS,
        resource::{Path, ResourceId, Service, SpaceId},
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

    fn test_hook_runtime() -> HookRuntime {
        HookRuntime::new(HooksConfig::default(), [7u8; 32])
    }

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

    fn test_invocation(hook_path: &str) -> Result<(CoreInvocationInfo, String)> {
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
        let space_string = space.to_string();
        let hook_resource: ResourceId = space.clone().to_resource(
            "hooks".parse::<Service>()?,
            Some(hook_path.parse::<Path>()?),
            None,
            None,
        );

        let delegation = Cid::new_v1(0x55, Code::Blake3_256.digest(b"delegation"));
        let invocation = make_invocation(
            vec![(
                hook_resource,
                vec!["tinycloud.hooks/subscribe".parse::<Ability>()?],
            )],
            &delegation,
            &jwk,
            &verification_method,
            4_102_444_800.0,
            InvocationOptions::default(),
        )?;

        Ok((CoreInvocationInfo::try_from(invocation)?, space_string))
    }

    #[tokio::test]
    async fn normalizes_and_validates_webhook_request() {
        let request = HookWebhookRequest {
            space: "tinycloud:space".to_string(),
            service: "kv".to_string(),
            path_prefix: Some("/documents/".to_string()),
            abilities: vec!["tinycloud.kv/put".to_string()],
            callback_url: "https://example.com/hooks".to_string(),
            secret: "dev-secret".to_string(),
        };

        let normalized = normalize_webhook_request(&request).expect("valid webhook request");
        assert_eq!(normalized.path_prefix.as_deref(), Some("documents"));
    }

    #[tokio::test]
    async fn converts_subscription_model_without_secret() {
        let model = hook_subscription::Model {
            id: "sub_01".to_string(),
            subscriber_did: "did:key:test".to_string(),
            space_id: "tinycloud:space".to_string(),
            target_service: "kv".to_string(),
            path_prefix: Some("documents".to_string()),
            abilities_json: Some(
                serde_json::to_string(&vec!["tinycloud.kv/put".to_string()]).unwrap(),
            ),
            callback_url: "https://example.com/hooks".to_string(),
            encrypted_secret: vec![1, 2, 3],
            secret_key_id: HOOK_WEBHOOK_SECRET_KEY_ID.to_string(),
            active: true,
            created_at: "2026-04-09T00:00:00Z".to_string(),
        };

        let response = webhook_response_from_model(&model).expect("response");
        assert_eq!(response.id, "sub_01");
        assert_eq!(response.secret_key_id, HOOK_WEBHOOK_SECRET_KEY_ID);
        assert_eq!(response.abilities, vec!["tinycloud.kv/put".to_string()]);
    }

    #[tokio::test]
    async fn authorizes_all_hook_management_abilities_on_matching_scope() -> Result<()> {
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
        let space_string = space.to_string();
        let hook_resource: ResourceId = space.clone().to_resource(
            "hooks".parse::<Service>()?,
            Some("kv/documents".parse::<Path>()?),
            None,
            None,
        );
        let delegation = Cid::new_v1(0x55, Code::Blake3_256.digest(b"delegation"));
        let invocation = make_invocation(
            vec![(
                hook_resource,
                vec![
                    "tinycloud.hooks/register".parse::<Ability>()?,
                    "tinycloud.hooks/list".parse::<Ability>()?,
                    "tinycloud.hooks/unregister".parse::<Ability>()?,
                ],
            )],
            &delegation,
            &jwk,
            &verification_method,
            4_102_444_800.0,
            InvocationOptions::default(),
        )?;
        let invocation = CoreInvocationInfo::try_from(invocation)?;
        let subscription = HookSubscription {
            space: space_string,
            service: "kv".to_string(),
            path_prefix: Some("documents".to_string()),
            abilities: vec!["tinycloud.kv/put".to_string()],
        };

        assert!(is_hook_action_authorized(
            &invocation,
            &subscription,
            "tinycloud.hooks/register"
        ));
        assert!(is_hook_action_authorized(
            &invocation,
            &subscription,
            "tinycloud.hooks/list"
        ));
        assert!(is_hook_action_authorized(
            &invocation,
            &subscription,
            "tinycloud.hooks/unregister"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn mints_ticket_for_authorized_scope() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let hooks = test_hook_runtime();
        let (invocation, space) = test_invocation("kv/documents")?;
        let request = HookTicketRequest {
            subscriptions: vec![HookSubscription {
                space,
                service: "kv".to_string(),
                path_prefix: Some("documents".to_string()),
                abilities: vec!["tinycloud.kv/put".to_string()],
            }],
            ttl_seconds: Some(60),
        };

        let response = mint_hook_ticket(&invocation, request, &hooks, &tinycloud)
            .await
            .expect("ticket");
        let claims = hooks.verify_ticket(&response.ticket).unwrap();
        assert_eq!(claims.sub, invocation.invoker);
        assert_eq!(claims.scopes.len(), 1);
        assert_eq!(claims.scopes[0].service, "kv");
        assert_eq!(claims.scopes[0].path_prefix.as_deref(), Some("documents"));
        Ok(())
    }

    #[tokio::test]
    async fn mints_ticket_for_sql_scope() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let hooks = test_hook_runtime();
        let (invocation, space) = test_invocation("sql/main.db")?;
        let request = HookTicketRequest {
            subscriptions: vec![HookSubscription {
                space,
                service: "sql".to_string(),
                path_prefix: Some("main.db".to_string()),
                abilities: vec!["tinycloud.sql/write".to_string()],
            }],
            ttl_seconds: Some(60),
        };

        let response = mint_hook_ticket(&invocation, request, &hooks, &tinycloud)
            .await
            .expect("ticket");
        let claims = hooks.verify_ticket(&response.ticket).unwrap();
        assert_eq!(claims.scopes[0].service, "sql");
        assert_eq!(claims.scopes[0].path_prefix.as_deref(), Some("main.db"));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_partially_authorized_ticket_requests() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let hooks = test_hook_runtime();
        let (invocation, space) = test_invocation("kv/documents")?;

        let request = HookTicketRequest {
            subscriptions: vec![
                HookSubscription {
                    space: space.clone(),
                    service: "kv".to_string(),
                    path_prefix: Some("documents".to_string()),
                    abilities: vec!["tinycloud.kv/put".to_string()],
                },
                HookSubscription {
                    space,
                    service: "kv".to_string(),
                    path_prefix: Some("private".to_string()),
                    abilities: vec!["tinycloud.kv/put".to_string()],
                },
            ],
            ttl_seconds: Some(60),
        };

        let err = mint_hook_ticket(&invocation, request, &hooks, &tinycloud)
            .await
            .expect_err("should reject mixed authorization");
        assert_eq!(err.0, Status::Forbidden);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_wrong_space_subscription() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let hooks = test_hook_runtime();
        let (invocation, _space) = test_invocation("kv/documents")?;
        let request = HookTicketRequest {
            subscriptions: vec![HookSubscription {
                space: "tinycloud:other-space".to_string(),
                service: "kv".to_string(),
                path_prefix: Some("documents".to_string()),
                abilities: vec!["tinycloud.kv/put".to_string()],
            }],
            ttl_seconds: Some(60),
        };

        let err = mint_hook_ticket(&invocation, request, &hooks, &tinycloud)
            .await
            .expect_err("should reject wrong space");
        assert_eq!(err.0, Status::Forbidden);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_unknown_hook_service() {
        let err = validate_subscription(&HookSubscription {
            space: "tinycloud:space".to_string(),
            service: "ftp".to_string(),
            path_prefix: Some("main".to_string()),
            abilities: vec!["tinycloud.ftp/execute".to_string()],
        })
        .expect_err("invalid service should be rejected");

        assert_eq!(err.0, Status::BadRequest);
    }

    #[tokio::test]
    async fn accepts_sql_and_duckdb_subscription_filters() {
        validate_subscription(&HookSubscription {
            space: "tinycloud:space".to_string(),
            service: "sql".to_string(),
            path_prefix: Some("analytics".to_string()),
            abilities: vec!["tinycloud.sql/write".to_string()],
        })
        .expect("sql subscription should be allowed");

        validate_subscription(&HookSubscription {
            space: "tinycloud:space".to_string(),
            service: "duckdb".to_string(),
            path_prefix: Some("analytics".to_string()),
            abilities: vec!["tinycloud.duckdb/write".to_string()],
        })
        .expect("duckdb subscription should be allowed");
    }

    #[tokio::test]
    async fn rejects_non_write_sql_subscription_filters() {
        let err = validate_subscription(&HookSubscription {
            space: "tinycloud:space".to_string(),
            service: "sql".to_string(),
            path_prefix: Some("analytics".to_string()),
            abilities: vec!["tinycloud.sql/read".to_string()],
        })
        .expect_err("read-only sql filter should be rejected");

        assert_eq!(err.0, Status::BadRequest);
    }

    #[tokio::test]
    async fn rejects_non_write_duckdb_subscription_filters() {
        let err = validate_subscription(&HookSubscription {
            space: "tinycloud:space".to_string(),
            service: "duckdb".to_string(),
            path_prefix: Some("analytics".to_string()),
            abilities: vec!["tinycloud.duckdb/import".to_string()],
        })
        .expect_err("non-write duckdb filter should be rejected");

        assert_eq!(err.0, Status::BadRequest);
    }
}
