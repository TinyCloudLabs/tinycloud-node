use crate::{
    authorization::AuthHeaderGetter,
    config::Config,
    hooks::{
        hook_scope_path, matches_scope, normalize_path_prefix, HookRuntime, HookSubscription,
        HookTicketClaims, HookTicketRequest, HookTicketResponse,
    },
    invocation_replay::InvocationReplayCache,
    policy_v3::PolicyV3Runtime,
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
use std::{net::IpAddr, time::Duration, time::Instant};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_core::{
    events::Invocation,
    hash::Blake3Hasher,
    hash::Hash,
    models::{delegation, hook_subscription},
    sea_orm::{ColumnTrait, EntityTrait, QueryFilter},
    types::Resource,
    util::InvocationInfo,
    AdmittedInvocation, ColumnEncryption,
};

/// An invocation whose signature, lifetime cap, delegation chain, revocation
/// status, time windows, and Policy/v3 session edge have been checked against
/// the node's authorization graph. The `Authorization` request guard only
/// decodes the header, so hook scope checks accept only this type: a claimed
/// capability is never trusted until [`authorize_hook_request`] has proven it
/// is delegated.
struct VerifiedHookInvocation {
    admitted: AdmittedInvocation,
    policy_session: bool,
}

impl VerifiedHookInvocation {
    fn info(&self) -> &InvocationInfo {
        &self.admitted.invocation().0
    }

    /// Spend the invocation in the `/invoke` replay cache. Routes call this
    /// only after every authorization check has passed, immediately before
    /// their effect, so a refused request writes nothing and a captured header
    /// cannot be replayed.
    async fn consume(
        &self,
        replay: &InvocationReplayCache,
        config: &Config,
    ) -> Result<(), (Status, String)> {
        if self.policy_session {
            replay
                .check_and_insert_invoker_nonce(self.admitted.invocation(), 60)
                .await?;
        } else {
            replay
                .check_and_insert(&self.admitted, config.invocation.max_lifetime_secs)
                .await?;
        }
        Ok(())
    }
}

/// Authorize a hooks request, read-only, before any route reads the
/// invocation's claimed scope.
///
/// The ordinary `verify_auth` path runs `TinyCloud::invoke`, which records the
/// invocation and executes mutations such as `tinycloud.kv/del` that need no
/// input. Hooks requests therefore first refuse any capability outside the
/// `hooks` service, then apply `/invoke`'s admission (signature, lifetime cap),
/// the read-only invocation kernel (delegation chain, revocation, time
/// windows), and the Policy/v3 gate. No space is looked up and nothing is
/// written here; see [`VerifiedHookInvocation::consume`].
async fn authorize_hook_request(
    span: &'static str,
    invocation: Invocation,
    tinycloud: &TinyCloud,
    policy_v3: &PolicyV3Runtime,
    config: &Config,
) -> Result<VerifiedHookInvocation, (Status, String)> {
    let capabilities = &invocation.0.capabilities;
    if capabilities.is_empty() || !capabilities.iter().all(is_hook_capability) {
        return Err((
            Status::Forbidden,
            "hooks requests may only invoke tinycloud.hooks capabilities".to_string(),
        ));
    }
    let now = OffsetDateTime::now_utc();
    let start = Instant::now();
    let admitted = authorize_admitted(invocation, tinycloud, config, now).await;
    crate::prometheus::observe_span(
        span,
        if admitted.is_ok() { "ok" } else { "error" },
        start.elapsed(),
    );
    let admitted = admitted?;
    let policy_session = policy_v3
        .authorize_invocation(tinycloud, &admitted.invocation().0, now)
        .await
        .map_err(|error| (Status::Forbidden, error.to_string()))?;
    Ok(VerifiedHookInvocation {
        admitted,
        policy_session,
    })
}

async fn authorize_admitted(
    invocation: Invocation,
    tinycloud: &TinyCloud,
    config: &Config,
    now: OffsetDateTime,
) -> Result<AdmittedInvocation, (Status, String)> {
    let admitted = AdmittedInvocation::admit(invocation, config.invocation.max_lifetime_secs)
        .await
        .map_err(|error| (Status::Unauthorized, error.to_string()))?;
    tinycloud
        .authorize_admitted(&admitted, now)
        .await
        .map_err(|error| (Status::Unauthorized, error.to_string()))?;
    Ok(admitted)
}

fn is_hook_capability(capability: &tinycloud_core::util::Capability) -> bool {
    matches!(&capability.resource, Resource::TinyCloud(resource) if resource.service().as_str() == "hooks")
        && capability
            .ability
            .as_ref()
            .as_ref()
            .starts_with("tinycloud.hooks/")
}

#[post("/hooks/tickets", format = "json", data = "<request>")]
#[allow(clippy::too_many_arguments)]
pub async fn create_hook_ticket(
    invocation: AuthHeaderGetter<InvocationInfo>,
    request: Json<HookTicketRequest>,
    hooks: &State<HookRuntime>,
    tinycloud: &State<TinyCloud>,
    policy_v3: &State<PolicyV3Runtime>,
    replay: &State<InvocationReplayCache>,
    config: &State<Config>,
) -> Result<Json<HookTicketResponse>, (Status, String)> {
    let invocation = authorize_hook_request(
        "server.hooks.ticket.auth",
        invocation.0,
        tinycloud,
        policy_v3,
        config,
    )
    .await?;
    let mut request = request.into_inner();
    authorize_ticket_scopes(&invocation, &mut request, hooks)?;
    // Build and sign the whole ticket first: a refused request (for example a
    // TTL that expires immediately) must not spend the invocation.
    let ticket = mint_hook_ticket(&invocation, request, hooks, tinycloud).await?;
    invocation.consume(replay, config).await?;
    Ok(Json(ticket))
}

/// Validate the requested subscriptions and require each to be covered by the
/// verified invocation.
fn authorize_ticket_scopes(
    verified: &VerifiedHookInvocation,
    request: &mut HookTicketRequest,
    hooks: &HookRuntime,
) -> Result<(), (Status, String)> {
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
        if !is_subscription_authorized(verified, subscription) {
            return Err((
                Status::Forbidden,
                "requested hook scope is not authorized".to_string(),
            ));
        }
    }
    Ok(())
}

async fn mint_hook_ticket(
    verified: &VerifiedHookInvocation,
    request: HookTicketRequest,
    hooks: &HookRuntime,
    tinycloud: &TinyCloud,
) -> Result<HookTicketResponse, (Status, String)> {
    let invocation = verified.info();

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
#[allow(clippy::too_many_arguments)]
pub async fn create_webhook(
    invocation: AuthHeaderGetter<InvocationInfo>,
    request: Json<HookWebhookRequest>,
    hooks: &State<HookRuntime>,
    tinycloud: &State<TinyCloud>,
    webhook_encryption: &State<ColumnEncryption>,
    policy_v3: &State<PolicyV3Runtime>,
    replay: &State<InvocationReplayCache>,
    config: &State<Config>,
) -> Result<Json<HookWebhookResponse>, (Status, String)> {
    let invocation = authorize_hook_request(
        "server.hooks.webhook_register.auth",
        invocation.0,
        tinycloud,
        policy_v3,
        config,
    )
    .await?;
    let normalized = normalize_webhook_request(&request)?;
    if !is_hook_action_authorized(&invocation, &normalized, "tinycloud.hooks/register") {
        return Err((
            Status::Forbidden,
            "webhook scope is not authorized".to_string(),
        ));
    }
    // Resolve the callback host only for an authorized caller.
    let callback_url = validate_webhook_callback_url(&request.callback_url).await?;

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
    invocation.consume(replay, config).await?;

    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("current timestamps should format as RFC3339");
    let model = hook_subscription::Model {
        id: hook_subscription_id(
            &invocation.info().invoker,
            &normalized,
            callback_url.as_str(),
            &created_at,
        ),
        subscriber_did: invocation.info().invoker.clone(),
        space_id: normalized.space.clone(),
        target_service: normalized.service.clone(),
        path_prefix: normalized.path_prefix.clone(),
        abilities_json: hook_subscription::Model::set_abilities(&normalized.abilities),
        callback_url: callback_url.to_string(),
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
    policy_v3: &State<PolicyV3Runtime>,
    replay: &State<InvocationReplayCache>,
    config: &State<Config>,
) -> Result<Json<Vec<HookWebhookResponse>>, (Status, String)> {
    let invocation = authorize_hook_request(
        "server.hooks.webhook_list.auth",
        invocation.0,
        tinycloud,
        policy_v3,
        config,
    )
    .await?;
    let normalized_prefix = normalize_path_prefix(query.prefix.clone());
    let requested_scope = HookSubscription {
        space: query.space.clone(),
        service: query.service.clone(),
        path_prefix: normalized_prefix.clone(),
        abilities: Vec::new(),
    };

    validate_subscription(&requested_scope)?;
    if !is_hook_action_authorized(&invocation, &requested_scope, "tinycloud.hooks/list") {
        return Err((
            Status::Forbidden,
            "webhook scope is not authorized".to_string(),
        ));
    }
    invocation.consume(replay, config).await?;

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
    policy_v3: &State<PolicyV3Runtime>,
    replay: &State<InvocationReplayCache>,
    config: &State<Config>,
) -> Result<Status, (Status, String)> {
    // Authenticate before the lookup so an unauthenticated caller cannot probe
    // which subscription ids exist.
    let invocation = authorize_hook_request(
        "server.hooks.webhook_unregister.auth",
        invocation.0,
        tinycloud,
        policy_v3,
        config,
    )
    .await?;
    // A subscription the caller may not unregister is reported exactly like a
    // missing one, so the route is not an oracle for other callers' ids.
    let not_found = || {
        (
            Status::NotFound,
            "webhook subscription not found".to_string(),
        )
    };
    let subscription = tinycloud
        .find_hook_subscription(subscription_id)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?
        .ok_or_else(not_found)?;

    let requested_scope = HookSubscription {
        space: subscription.space_id.clone(),
        service: subscription.target_service.clone(),
        path_prefix: subscription.path_prefix.clone(),
        abilities: subscription
            .abilities()
            .map_err(|e| (Status::InternalServerError, e.to_string()))?,
    };
    if !is_hook_action_authorized(&invocation, &requested_scope, "tinycloud.hooks/unregister") {
        return Err(not_found());
    }
    invocation.consume(replay, config).await?;

    tinycloud
        .deactivate_hook_subscription(subscription_id)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;
    Ok(Status::NoContent)
}

fn validate_subscription(subscription: &HookSubscription) -> Result<(), (Status, String)> {
    let service = subscription.service.as_str();
    if !(matches!(service, "kv" | "sql") || cfg!(feature = "duckdb") && service == "duckdb") {
        return Err((Status::BadRequest, "Unsupported hook service".to_string()));
    }

    let allowed_abilities: &[&str] = match service {
        "kv" => &["tinycloud.kv/put", "tinycloud.kv/del"],
        "sql" => &["tinycloud.sql/write"],
        "duckdb" if cfg!(feature = "duckdb") => &["tinycloud.duckdb/write"],
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
    invocation: &VerifiedHookInvocation,
    subscription: &HookSubscription,
) -> bool {
    is_hook_action_authorized(invocation, subscription, "tinycloud.hooks/subscribe")
}

fn is_hook_action_authorized(
    verified: &VerifiedHookInvocation,
    subscription: &HookSubscription,
    ability: &str,
) -> bool {
    let requested_scope =
        hook_scope_path(&subscription.service, subscription.path_prefix.as_deref());

    verified.info().capabilities.iter().any(|capability| {
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

    let url = reqwest::Url::parse(&request.callback_url)
        .map_err(|e| (Status::BadRequest, format!("invalid callbackUrl: {e}")))?;
    validate_webhook_url_shape(&url)?;

    Ok(subscription)
}

fn validate_webhook_url_shape(url: &reqwest::Url) -> Result<(), (Status, String)> {
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(443)
    {
        return Err((
            Status::BadRequest,
            "callbackUrl must be canonical HTTPS on port 443 without userinfo or fragments"
                .to_string(),
        ));
    }
    let Some(host) = url.host_str() else {
        return Err((
            Status::BadRequest,
            "callbackUrl host is required".to_string(),
        ));
    };
    if host.is_empty() || host.contains('.') && host.ends_with('.') {
        return Err((
            Status::BadRequest,
            "callbackUrl host is not canonical".to_string(),
        ));
    }
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        if blocked_webhook_ip(ip) {
            return Err((
                Status::BadRequest,
                "callbackUrl resolves to a reserved address".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn blocked_webhook_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            let first = octets[0];
            let second = octets[1];
            (first == 0)
                || (first == 10)
                || (first == 100 && (64..=127).contains(&second))
                || (first == 127)
                || (first == 169 && second == 254)
                || (first == 172 && (16..=31).contains(&second))
                || (first == 192 && (second == 0 || second == 2 || second == 168))
                || (first == 192 && second == 88 && octets[2] == 99)
                || (first == 198 && (second == 18 || second == 19 || second == 51))
                || (first == 203 && second == 0 && octets[2] == 113)
                || first >= 224
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| blocked_webhook_ip(mapped.into()))
        }
    }
}

pub async fn validate_webhook_callback_url(
    callback_url: &str,
) -> Result<reqwest::Url, (Status, String)> {
    let url = reqwest::Url::parse(callback_url)
        .map_err(|e| (Status::BadRequest, format!("invalid callbackUrl: {e}")))?;
    #[cfg(test)]
    if url.scheme() == "http"
        && url
            .host_str()
            .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback())
    {
        return Ok(url);
    }
    validate_webhook_url_shape(&url)?;
    let host = url.host_str().ok_or_else(|| {
        (
            Status::BadRequest,
            "callbackUrl host is required".to_string(),
        )
    })?;
    let port = url
        .port_or_known_default()
        .expect("HTTPS has a default port");
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| {
            (
                Status::BadRequest,
                "callbackUrl host cannot be resolved".to_string(),
            )
        })?
        .collect::<Vec<_>>();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| blocked_webhook_ip(address.ip()))
    {
        return Err((
            Status::BadRequest,
            "callbackUrl resolves to a reserved address".to_string(),
        ));
    }
    Ok(url)
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

    /// Admits a signed invocation as a non-policy session, skipping only the
    /// delegation-chain check: scope-matching tests below exercise the claimed
    /// scope logic that runs after [`authorize_hook_request`].
    async fn verified(
        invocation: tinycloud_auth::authorization::TinyCloudInvocation,
    ) -> Result<VerifiedHookInvocation> {
        let invocation = Invocation::from_header_ser::<
            tinycloud_auth::authorization::TinyCloudInvocation,
        >(&invocation.encode()?)
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        Ok(VerifiedHookInvocation {
            admitted: AdmittedInvocation::admit(invocation, 300).await?,
            policy_session: false,
        })
    }

    async fn mint(
        verified: &VerifiedHookInvocation,
        mut request: HookTicketRequest,
        hooks: &HookRuntime,
        tinycloud: &TinyCloud,
    ) -> Result<HookTicketResponse, (Status, String)> {
        authorize_ticket_scopes(verified, &mut request, hooks)?;
        mint_hook_ticket(verified, request, hooks, tinycloud).await
    }

    /// Scope-matching fixture: wraps the invocation as already verified, so it
    /// exercises only the claimed-scope checks that run after
    /// [`authorize_hook_request`]. Route tests below cover authentication.
    async fn test_invocation(hook_path: &str) -> Result<(VerifiedHookInvocation, String)> {
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
            (OffsetDateTime::now_utc().unix_timestamp() + 240) as f64,
            InvocationOptions::default(),
        )?;

        Ok((verified(invocation).await?, space_string))
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

    #[test]
    fn rejects_webhook_urls_that_cross_the_egress_boundary() {
        for callback_url in [
            "http://example.com/hooks",
            "https://user:password@example.com/hooks",
            "https://example.com:8443/hooks",
            "https://127.0.0.1/hooks",
            "https://[::1]/hooks",
            "https://example.com/hooks#fragment",
        ] {
            let request = HookWebhookRequest {
                space: "tinycloud:space".to_string(),
                service: "kv".to_string(),
                path_prefix: None,
                abilities: vec!["tinycloud.kv/put".to_string()],
                callback_url: callback_url.to_string(),
                secret: "dev-secret".to_string(),
            };
            assert!(
                normalize_webhook_request(&request).is_err(),
                "{callback_url}"
            );
        }
    }

    #[test]
    fn blocks_private_and_reserved_webhook_addresses() {
        for address in [
            "10.0.0.1",
            "100.64.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(blocked_webhook_ip(address.parse().unwrap()), "{address}");
        }
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
            (OffsetDateTime::now_utc().unix_timestamp() + 240) as f64,
            InvocationOptions::default(),
        )?;
        let invocation = verified(invocation).await?;
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
    async fn mints_ticket_for_sql_scope() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let hooks = test_hook_runtime();
        let (invocation, space) = test_invocation("sql/main.db").await?;
        let request = HookTicketRequest {
            subscriptions: vec![HookSubscription {
                space,
                service: "sql".to_string(),
                path_prefix: Some("main.db".to_string()),
                abilities: vec!["tinycloud.sql/write".to_string()],
            }],
            ttl_seconds: Some(60),
        };

        let response = mint(&invocation, request, &hooks, &tinycloud)
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
        let (invocation, space) = test_invocation("kv/documents").await?;

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

        let err = mint(&invocation, request, &hooks, &tinycloud)
            .await
            .expect_err("should reject mixed authorization");
        assert_eq!(err.0, Status::Forbidden);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_wrong_space_subscription() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let hooks = test_hook_runtime();
        let (invocation, _space) = test_invocation("kv/documents").await?;
        let request = HookTicketRequest {
            subscriptions: vec![HookSubscription {
                space: "tinycloud:other-space".to_string(),
                service: "kv".to_string(),
                path_prefix: Some("documents".to_string()),
                abilities: vec!["tinycloud.kv/put".to_string()],
            }],
            ttl_seconds: Some(60),
        };

        let err = mint(&invocation, request, &hooks, &tinycloud)
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
    async fn accepts_sql_subscription_filters() {
        validate_subscription(&HookSubscription {
            space: "tinycloud:space".to_string(),
            service: "sql".to_string(),
            path_prefix: Some("analytics".to_string()),
            abilities: vec!["tinycloud.sql/write".to_string()],
        })
        .expect("sql subscription should be allowed");
    }

    #[cfg(feature = "duckdb")]
    #[tokio::test]
    async fn accepts_duckdb_subscription_filters() {
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

    /// A node with two stored spaces, a delegated session key, and the hooks
    /// routes mounted with the same managed state as production.
    struct HookRouteFixture {
        client: rocket::local::asynchronous::Client,
        db: tinycloud_core::sea_orm::DatabaseConnection,
        tinycloud: TinyCloud,
        space: SpaceId,
        other_space: SpaceId,
        owner: (JWK, String),
        session: (JWK, String),
        session_proof: Cid,
    }

    fn did_key() -> Result<(JWK, String)> {
        let jwk = JWK::generate_ed25519()?;
        let did = DID_METHODS.generate(&jwk, "key")?.to_string();
        let fragment = did
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("missing did:key fragment"))?
            .1
            .to_string();
        let verification_method = format!("{did}#{fragment}");
        Ok((jwk, verification_method))
    }

    fn did_of(verification_method: &str) -> &str {
        verification_method
            .split_once('#')
            .map_or(verification_method, |(did, _)| did)
    }

    fn space_of(verification_method: &str) -> Result<SpaceId> {
        Ok(SpaceId::new(
            did_of(verification_method).parse::<DIDBuf>()?,
            "alpha".parse()?,
        ))
    }

    /// `path == ""` is the whole service, as in the node SDK's default session
    /// grant of `hooks`.
    fn resource(space: &SpaceId, service: &str, path: &str) -> Result<ResourceId> {
        Ok(space.clone().to_resource(
            service.parse::<Service>()?,
            (!path.is_empty())
                .then(|| path.parse::<Path>())
                .transpose()?,
            None,
            None,
        ))
    }

    /// Stores an owner -> session delegation granting `(service, path,
    /// ability)` on the owner's space, plus a second owner's space for
    /// cross-space attempts.
    async fn hook_route_fixture(grants: &[(&str, &str, &str)]) -> Result<HookRouteFixture> {
        use tinycloud_core::{
            models::{abilities, actor, space},
            sea_orm::{ActiveModelTrait, ActiveValue::Set},
            types::{Ability as CoreAbility, Caveats, SpaceIdWrap},
        };

        use tinycloud_core::storage::StorageSetup;

        let owner = did_key()?;
        let (_, other_owner) = did_key()?;
        let session = did_key()?;
        let space = space_of(&owner.1)?;
        let other_space = space_of(&other_owner)?;

        let tempdir = TempDir::new()?;
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string())).await?;
        let storage = NodeFileSystemConfig::new(tempdir.path()).open().await?;
        let _persisted = tempdir.keep();
        for id in [&space, &other_space] {
            storage.create(id).await?;
        }
        let tinycloud = TinyCloud::new(
            db.clone(),
            Either::B(storage),
            StaticSecret::new(vec![0u8; 32]).unwrap(),
        )
        .await?;
        for id in [&space, &other_space] {
            space::ActiveModel {
                id: Set(SpaceIdWrap(id.clone())),
            }
            .insert(&db)
            .await?;
        }
        for did in [did_of(&owner.1), did_of(&session.1)] {
            actor::ActiveModel {
                id: Set(did.to_string()),
            }
            .insert(&db)
            .await?;
        }

        let proof_hash = tinycloud_core::hash::hash(session.1.as_bytes());
        let now = OffsetDateTime::now_utc();
        delegation::ActiveModel {
            id: Set(proof_hash),
            delegator: Set(did_of(&owner.1).to_string()),
            delegatee: Set(did_of(&session.1).to_string()),
            expiry: Set(Some(now + time::Duration::hours(1))),
            issued_at: Set(Some(now)),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(b"hooks-session".to_vec()),
        }
        .insert(&db)
        .await?;
        for (service, path, ability) in grants {
            abilities::ActiveModel {
                delegation: Set(proof_hash),
                resource: Set(Resource::TinyCloud(resource(&space, service, path)?)),
                ability: Set(CoreAbility::try_from(ability.to_string()).unwrap()),
                caveats: Set(Caveats::default()),
            }
            .insert(&db)
            .await?;
        }

        let node = StaticSecret::new(vec![5u8; 32]).unwrap();
        let rocket = rocket::build()
            .mount(
                "/",
                rocket::routes![
                    create_hook_ticket,
                    create_webhook,
                    list_webhooks,
                    delete_webhook
                ],
            )
            .manage(tinycloud.clone())
            .manage(test_hook_runtime())
            .manage(ColumnEncryption::new([3u8; 32]))
            .manage(PolicyV3Runtime::new(db.clone(), node.node_did(), node))
            .manage(InvocationReplayCache::new(db.clone()))
            .manage(Config::default());

        Ok(HookRouteFixture {
            client: rocket::local::asynchronous::Client::tracked(rocket).await?,
            db,
            tinycloud,
            space,
            other_space,
            owner,
            session,
            session_proof: proof_hash.to_cid(0x55),
        })
    }

    /// Signs an invocation with `signer` while claiming `issuer` as its
    /// verification method, so a mismatched pair is a forged signature.
    fn signed_header(
        signer: &JWK,
        issuer: &str,
        proof: Vec<Cid>,
        capabilities: &[(ResourceId, &[&str])],
    ) -> Result<String> {
        signed_header_expiring(signer, issuer, proof, capabilities, 240)
    }

    fn signed_header_expiring(
        signer: &JWK,
        issuer: &str,
        proof: Vec<Cid>,
        capabilities: &[(ResourceId, &[&str])],
        lifetime_secs: i64,
    ) -> Result<String> {
        let expiration = (OffsetDateTime::now_utc().unix_timestamp() + lifetime_secs) as f64;
        let unused = Cid::new_v1(0x55, Code::Blake3_256.digest(b"unused"));
        let capabilities = capabilities
            .iter()
            .map(|(resource, abilities)| {
                Ok((
                    resource.clone(),
                    abilities
                        .iter()
                        .map(|ability| ability.parse::<Ability>())
                        .collect::<Result<Vec<_>, _>>()?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let invocation = make_invocation(
            capabilities,
            &unused,
            signer,
            issuer,
            expiration,
            InvocationOptions {
                proof: Some(proof),
                ..Default::default()
            },
        )?;
        Ok(invocation.encode()?)
    }

    impl HookRouteFixture {
        fn hooks(&self, path: &str) -> Result<ResourceId> {
            resource(&self.space, "hooks", path)
        }

        fn session_header(&self, capabilities: &[(ResourceId, &[&str])]) -> Result<String> {
            signed_header(
                &self.session.0,
                &self.session.1,
                vec![self.session_proof],
                capabilities,
            )
        }

        /// Stranger key signing as the delegated session key.
        fn forged_header(&self, capabilities: &[(ResourceId, &[&str])]) -> Result<String> {
            let (stranger, _) = did_key()?;
            signed_header(
                &stranger,
                &self.session.1,
                vec![self.session_proof],
                capabilities,
            )
        }

        async fn ticket(
            &self,
            header: String,
            space: &SpaceId,
            service: &str,
            prefix: &str,
        ) -> (Status, String) {
            self.ticket_with_ttl(header, space, service, prefix, 60)
                .await
        }

        async fn ticket_with_ttl(
            &self,
            header: String,
            space: &SpaceId,
            service: &str,
            prefix: &str,
            ttl_seconds: u64,
        ) -> (Status, String) {
            let response = self
                .client
                .post("/hooks/tickets")
                .header(rocket::http::Header::new("Authorization", header))
                .header(rocket::http::ContentType::JSON)
                .body(
                    serde_json::json!({
                        "subscriptions": [{
                            "space": space.to_string(),
                            "service": service,
                            "pathPrefix": prefix,
                        }],
                        "ttlSeconds": ttl_seconds,
                    })
                    .to_string(),
                )
                .dispatch()
                .await;
            (
                response.status(),
                response.into_string().await.unwrap_or_default(),
            )
        }

        async fn register(&self, header: String, space: &SpaceId) -> (Status, String) {
            let response = self
                .client
                .post("/hooks/webhooks")
                .header(rocket::http::Header::new("Authorization", header))
                .header(rocket::http::ContentType::JSON)
                .body(
                    serde_json::json!({
                        "space": space.to_string(),
                        "service": "kv",
                        "pathPrefix": "documents",
                        // Public IP literal: passes egress checks without DNS.
                        "callbackUrl": "https://1.1.1.1/hooks",
                        "secret": "webhook-secret",
                    })
                    .to_string(),
                )
                .dispatch()
                .await;
            (
                response.status(),
                response.into_string().await.unwrap_or_default(),
            )
        }

        async fn list(&self, header: String) -> (Status, String) {
            let response = self
                .client
                .get(format!(
                    "/hooks/webhooks?space={}&service=kv&prefix=documents",
                    self.space
                ))
                .header(rocket::http::Header::new("Authorization", header))
                .dispatch()
                .await;
            (
                response.status(),
                response.into_string().await.unwrap_or_default(),
            )
        }

        async fn unregister(&self, header: String, id: &str) -> (Status, String) {
            let response = self
                .client
                .delete(format!("/hooks/webhooks/{id}"))
                .header(rocket::http::Header::new("Authorization", header))
                .dispatch()
                .await;
            (
                response.status(),
                response.into_string().await.unwrap_or_default(),
            )
        }

        /// Row counts for every table a hooks request could plausibly write.
        async fn persisted_rows(&self) -> Result<[u64; 5]> {
            use tinycloud_core::{
                models::{current_kv, invocation, invocation_replay},
                sea_orm::PaginatorTrait,
            };
            Ok([
                invocation::Entity::find().count(&self.db).await?,
                invocation_replay::Entity::find().count(&self.db).await?,
                delegation::Entity::find().count(&self.db).await?,
                current_kv::Entity::find().count(&self.db).await?,
                hook_subscription::Entity::find().count(&self.db).await?,
            ])
        }
    }

    const SUBSCRIBE: &[&str] = &["tinycloud.hooks/subscribe"];

    #[tokio::test]
    async fn whole_service_hooks_grant_covers_scoped_ticket() -> Result<()> {
        let fixture = hook_route_fixture(&[("hooks", "", "tinycloud.hooks/subscribe")]).await?;
        let header = fixture.session_header(&[(fixture.hooks("kv/documents")?, SUBSCRIBE)])?;
        let (status, _) = fixture
            .ticket(header, &fixture.space, "kv", "documents")
            .await;
        assert_eq!(status, Status::Ok);
        Ok(())
    }

    #[tokio::test]
    async fn delegated_sql_scope_mints_ticket() -> Result<()> {
        let fixture = hook_route_fixture(&[(
            "hooks",
            "sql/conversations/conversation",
            "tinycloud.hooks/subscribe",
        )])
        .await?;
        let header = fixture
            .session_header(&[(fixture.hooks("sql/conversations/conversation")?, SUBSCRIBE)])?;
        let (status, body) = fixture
            .ticket(header, &fixture.space, "sql", "conversations/conversation")
            .await;
        assert_eq!(status, Status::Ok, "{body}");
        let ticket: serde_json::Value = serde_json::from_str(&body)?;
        let claims = test_hook_runtime()
            .verify_ticket(ticket["ticket"].as_str().expect("ticket string"))
            .expect("node-signed ticket");
        assert_eq!(claims.scopes[0].service, "sql");
        assert_eq!(
            claims.scopes[0].path_prefix.as_deref(),
            Some("conversations/conversation")
        );
        Ok(())
    }

    #[tokio::test]
    async fn delegated_session_uses_every_hooks_route() -> Result<()> {
        let fixture = hook_route_fixture(&[
            ("hooks", "kv/documents", "tinycloud.hooks/subscribe"),
            ("hooks", "kv/documents", "tinycloud.hooks/register"),
            ("hooks", "kv/documents", "tinycloud.hooks/list"),
            ("hooks", "kv/documents", "tinycloud.hooks/unregister"),
        ])
        .await?;
        let scope = fixture.hooks("kv/documents")?;

        let (status, body) = fixture
            .ticket(
                fixture.session_header(&[(scope.clone(), SUBSCRIBE)])?,
                &fixture.space,
                "kv",
                "documents/inbox",
            )
            .await;
        assert_eq!(status, Status::Ok, "{body}");
        let ticket: serde_json::Value = serde_json::from_str(&body)?;
        let claims = test_hook_runtime()
            .verify_ticket(ticket["ticket"].as_str().expect("ticket string"))
            .expect("node-signed ticket");
        assert_eq!(claims.sub, did_of(&fixture.session.1));
        assert_eq!(
            claims.scopes[0].path_prefix.as_deref(),
            Some("documents/inbox")
        );

        let (status, body) = fixture
            .register(
                fixture.session_header(&[(scope.clone(), &["tinycloud.hooks/register"])])?,
                &fixture.space,
            )
            .await;
        assert_eq!(status, Status::Ok, "{body}");
        let registered: serde_json::Value = serde_json::from_str(&body)?;
        let id = registered["id"].as_str().expect("webhook id").to_string();

        let (status, body) = fixture
            .list(fixture.session_header(&[(scope.clone(), &["tinycloud.hooks/list"])])?)
            .await;
        assert_eq!(status, Status::Ok, "{body}");
        let listed: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(listed[0]["id"], id.as_str());

        let (status, _) = fixture
            .unregister(
                fixture.session_header(&[(scope, &["tinycloud.hooks/unregister"])])?,
                &id,
            )
            .await;
        assert_eq!(status, Status::NoContent);
        Ok(())
    }

    #[tokio::test]
    async fn refuses_hook_tickets_without_a_verified_delegation() -> Result<()> {
        let fixture =
            hook_route_fixture(&[("hooks", "kv/documents", "tinycloud.hooks/subscribe")]).await?;
        let scope = fixture.hooks("kv/documents")?;
        let claim = [(scope, SUBSCRIBE)];
        let (stranger_jwk, stranger) = did_key()?;
        let fabricated = Cid::new_v1(0x55, Code::Blake3_256.digest(b"never-delegated"));
        let signed = fixture.session_header(&claim)?;
        let (unsigned, _signature) = signed
            .rsplit_once('.')
            .ok_or_else(|| anyhow::anyhow!("JWT-encoded invocation"))?;

        let attempts = [
            ("unsigned token", format!("{unsigned}.")),
            ("forged session signature", fixture.forged_header(&claim)?),
            // Stranger signs honestly and borrows the session's proof.
            (
                "borrowed proof",
                signed_header(
                    &stranger_jwk,
                    &stranger,
                    vec![fixture.session_proof],
                    &claim,
                )?,
            ),
            (
                "no proof",
                signed_header(&stranger_jwk, &stranger, vec![], &claim)?,
            ),
            // The session key itself, citing a proof the node never stored.
            (
                "unstored proof",
                signed_header(
                    &fixture.session.0,
                    &fixture.session.1,
                    vec![fabricated],
                    &claim,
                )?,
            ),
        ];
        for (case, header) in attempts {
            let (status, body) = fixture
                .ticket(header, &fixture.space, "kv", "documents")
                .await;
            assert_eq!(status, Status::Unauthorized, "{case}: {body}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn refuses_claimed_but_undelegated_hook_abilities() -> Result<()> {
        let fixture =
            hook_route_fixture(&[("hooks", "kv/documents", "tinycloud.hooks/subscribe")]).await?;
        let documents = fixture.hooks("kv/documents")?;

        // Subscribe is delegated only on `kv/documents` of this space.
        let wider = fixture.session_header(&[(fixture.hooks("kv")?, SUBSCRIBE)])?;
        let (status, _) = fixture.ticket(wider, &fixture.space, "kv", "private").await;
        assert_eq!(status, Status::Unauthorized);
        let foreign = fixture.session_header(&[(
            resource(&fixture.other_space, "hooks", "kv/documents")?,
            SUBSCRIBE,
        )])?;
        let (status, _) = fixture
            .ticket(foreign, &fixture.other_space, "kv", "documents")
            .await;
        assert_eq!(status, Status::Unauthorized);

        // Management abilities were never delegated at all.
        let register =
            fixture.session_header(&[(documents.clone(), &["tinycloud.hooks/register"])])?;
        assert_eq!(
            fixture.register(register, &fixture.space).await.0,
            Status::Unauthorized
        );
        let list = fixture.session_header(&[(documents.clone(), &["tinycloud.hooks/list"])])?;
        assert_eq!(fixture.list(list).await.0, Status::Unauthorized);
        let unregister = fixture.session_header(&[(documents, &["tinycloud.hooks/unregister"])])?;
        assert_eq!(
            fixture.unregister(unregister, "any-subscription").await.0,
            Status::Unauthorized
        );
        Ok(())
    }

    #[tokio::test]
    async fn kv_only_delegation_cannot_claim_hooks() -> Result<()> {
        let fixture = hook_route_fixture(&[
            ("kv", "documents", "tinycloud.kv/get"),
            ("kv", "documents", "tinycloud.kv/list"),
        ])
        .await?;
        let header = fixture.session_header(&[(fixture.hooks("kv/documents")?, SUBSCRIBE)])?;
        let (status, _) = fixture
            .ticket(header, &fixture.space, "kv", "documents")
            .await;
        assert_eq!(status, Status::Unauthorized);
        Ok(())
    }

    /// P1: hooks routes must not execute or record any non-hooks capability,
    /// even a delegated `tinycloud.kv/del` that needs no input.
    #[tokio::test]
    async fn hooks_routes_never_execute_or_record_non_hook_capabilities() -> Result<()> {
        use futures::AsyncWriteExt;
        use tinycloud_core::storage::ImmutableStaging;

        let fixture = hook_route_fixture(&[
            ("kv", "documents/note", "tinycloud.kv/del"),
            ("hooks", "kv/documents", "tinycloud.hooks/subscribe"),
            ("hooks", "kv/documents", "tinycloud.hooks/register"),
        ])
        .await?;
        let key: Path = "documents/note".parse()?;
        let staging = crate::BlockStage::from(crate::config::StagingStorage::Memory);
        let mut stage = staging.stage(&fixture.space).await?;
        stage.write_all(b"keep me").await?;
        stage.flush().await?;
        fixture
            .tinycloud
            .invoke_internal_kv_put::<crate::BlockStage>(
                fixture.space.clone(),
                key.clone(),
                tinycloud_core::types::Metadata(Default::default()),
                stage,
                None,
            )
            .await
            .map_err(|error| anyhow::anyhow!("seed KV value: {error}"))?;
        let rows_before = fixture.persisted_rows().await?;

        let delete = (
            resource(&fixture.space, "kv", "documents/note")?,
            &["tinycloud.kv/del"][..],
        );
        let subscribe = (fixture.hooks("kv/documents")?, SUBSCRIBE);
        let register = (
            fixture.hooks("kv/documents")?,
            &["tinycloud.hooks/register"][..],
        );
        let cases = [
            ("ticket, kv/del only", true, vec![delete.clone()]),
            (
                "ticket, hooks + kv/del",
                true,
                vec![subscribe, delete.clone()],
            ),
            ("webhook, kv/del only", false, vec![delete.clone()]),
            ("webhook, hooks + kv/del", false, vec![register, delete]),
        ];
        for (case, ticket, capabilities) in cases {
            let header = fixture.session_header(&capabilities)?;
            let (status, body) = if ticket {
                fixture
                    .ticket(header, &fixture.space, "kv", "documents")
                    .await
            } else {
                fixture.register(header, &fixture.space).await
            };
            assert_eq!(status, Status::Forbidden, "{case}: {body}");
            assert!(
                fixture
                    .tinycloud
                    .kv_get(&fixture.space, &key)
                    .await
                    .is_ok_and(|v| v.is_some()),
                "{case}: key must survive"
            );
        }
        assert_eq!(fixture.persisted_rows().await?, rows_before);
        Ok(())
    }

    /// P2: a forged request is answered identically for a stored and a
    /// missing space.
    #[tokio::test]
    async fn forged_requests_do_not_reveal_whether_a_space_exists() -> Result<()> {
        let fixture =
            hook_route_fixture(&[("hooks", "kv/documents", "tinycloud.hooks/subscribe")]).await?;
        let (_, nobody) = did_key()?;
        let missing = space_of(&nobody)?;
        let mut tickets = Vec::new();
        let mut webhooks = Vec::new();
        let mut kv_claims = Vec::new();
        for space in [&fixture.space, &missing] {
            let ticket =
                fixture.forged_header(&[(resource(space, "hooks", "kv/documents")?, SUBSCRIBE)])?;
            tickets.push(fixture.ticket(ticket, space, "kv", "documents").await);
            let register = fixture.forged_header(&[(
                resource(space, "hooks", "kv/documents")?,
                &["tinycloud.hooks/register"],
            )])?;
            webhooks.push(fixture.register(register, space).await);
            // The reviewer's reproduction: a forged KV invocation, which the
            // KV write path used to answer 404 for a missing space.
            let kv = fixture.forged_header(&[(
                resource(space, "kv", "documents/note")?,
                &["tinycloud.kv/del"],
            )])?;
            kv_claims.push(fixture.ticket(kv, space, "kv", "documents").await);
        }
        assert_eq!(tickets[0].0, Status::Unauthorized);
        assert_eq!(tickets[0], tickets[1]);
        assert_eq!(webhooks[0].0, Status::Unauthorized);
        assert_eq!(webhooks[0], webhooks[1]);
        assert_eq!(kv_claims[0].0, Status::Forbidden);
        assert_eq!(kv_claims[0], kv_claims[1]);
        Ok(())
    }

    /// P3: unregistering a subscription the caller may not touch looks exactly
    /// like unregistering one that does not exist.
    #[tokio::test]
    async fn webhook_delete_does_not_reveal_inaccessible_ids() -> Result<()> {
        let fixture =
            hook_route_fixture(&[("hooks", "kv/documents", "tinycloud.hooks/subscribe")]).await?;
        let existing = fixture
            .tinycloud
            .create_hook_subscription(hook_subscription::Model {
                id: "sub_existing".to_string(),
                subscriber_did: "did:key:someone-else".to_string(),
                space_id: fixture.space.to_string(),
                target_service: "kv".to_string(),
                path_prefix: Some("documents".to_string()),
                abilities_json: None,
                callback_url: "https://1.1.1.1/hooks".to_string(),
                encrypted_secret: vec![1, 2, 3],
                secret_key_id: HOOK_WEBHOOK_SECRET_KEY_ID.to_string(),
                active: true,
                created_at: "2026-10-05T00:00:00Z".to_string(),
            })
            .await?;
        let scope = fixture.hooks("kv/documents")?;
        let inaccessible = fixture
            .unregister(
                fixture.session_header(&[(scope.clone(), SUBSCRIBE)])?,
                &existing.id,
            )
            .await;
        let missing = fixture
            .unregister(
                fixture.session_header(&[(scope, SUBSCRIBE)])?,
                "sub_missing",
            )
            .await;
        assert_eq!(inaccessible.0, Status::NotFound);
        assert_eq!(inaccessible, missing);
        assert!(
            fixture
                .tinycloud
                .find_hook_subscription(&existing.id)
                .await?
                .is_some_and(|row| row.active),
            "subscription stays active"
        );
        Ok(())
    }

    #[tokio::test]
    async fn hook_events_refuses_tickets_minted_under_the_pre_fix_key() -> Result<()> {
        let node = StaticSecret::new(vec![5u8; 32]).unwrap();
        let pre_fix = HookRuntime::new(
            HooksConfig::default(),
            node.derive_key(b"tinycloud/hooks/tickets"),
        );
        let current = HookRuntime::new(
            HooksConfig::default(),
            node.derive_key(crate::hooks::HOOK_TICKET_KEY_CONTEXT),
        );
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = HookTicketClaims {
            v: 1,
            sub: "did:key:subscriber".to_string(),
            scopes: vec![HookSubscription {
                space: "tinycloud:space".to_string(),
                service: "kv".to_string(),
                path_prefix: None,
                abilities: Vec::new(),
            }],
            iat: now,
            exp: now + 60,
            parent_exp: now + 60,
        };
        let stale = pre_fix.sign_ticket(&claims).unwrap();
        assert!(current
            .verify_ticket(&current.sign_ticket(&claims).unwrap())
            .is_ok());

        let client = rocket::local::asynchronous::Client::tracked(
            rocket::build()
                .mount("/", rocket::routes![hook_events])
                .manage(current),
        )
        .await?;
        let response = client
            .get(format!("/hooks/events?ticket={stale}"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized);
        Ok(())
    }

    /// Ordinary invoke semantics: the space owner is the root authority for
    /// its own space and needs no delegation.
    #[tokio::test]
    async fn space_owner_mints_ticket_without_a_delegation() -> Result<()> {
        let fixture = hook_route_fixture(&[]).await?;
        let header = signed_header(
            &fixture.owner.0,
            &fixture.owner.1,
            vec![],
            &[(fixture.hooks("kv/documents")?, SUBSCRIBE)],
        )?;
        let (status, body) = fixture
            .ticket(header, &fixture.space, "kv", "documents")
            .await;
        assert_eq!(status, Status::Ok, "{body}");
        // Root authority covers only the owner's own spaces.
        let foreign = signed_header(
            &fixture.owner.0,
            &fixture.owner.1,
            vec![],
            &[(
                resource(&fixture.other_space, "hooks", "kv/documents")?,
                SUBSCRIBE,
            )],
        )?;
        let (status, _) = fixture
            .ticket(foreign, &fixture.other_space, "kv", "documents")
            .await;
        assert_eq!(status, Status::Unauthorized);
        Ok(())
    }

    #[tokio::test]
    async fn revoked_delegation_is_refused() -> Result<()> {
        use tinycloud_core::{
            models::revocation,
            sea_orm::{ActiveModelTrait, ActiveValue::Set},
        };
        let fixture =
            hook_route_fixture(&[("hooks", "kv/documents", "tinycloud.hooks/subscribe")]).await?;
        let claim = [(fixture.hooks("kv/documents")?, SUBSCRIBE)];
        let (status, _) = fixture
            .ticket(
                fixture.session_header(&claim)?,
                &fixture.space,
                "kv",
                "documents",
            )
            .await;
        assert_eq!(status, Status::Ok);

        revocation::ActiveModel {
            id: Set(tinycloud_core::hash::hash(b"revoke-hooks-session")),
            revoker: Set(did_of(&fixture.owner.1).to_string()),
            revoked: Set(Hash::from(fixture.session_proof)),
            serialization: Set(b"revoke-hooks-session".to_vec()),
            revoked_at: Set(Some(OffsetDateTime::now_utc())),
        }
        .insert(&fixture.db)
        .await?;
        let (status, body) = fixture
            .ticket(
                fixture.session_header(&claim)?,
                &fixture.space,
                "kv",
                "documents",
            )
            .await;
        assert_eq!(status, Status::Unauthorized, "{body}");
        Ok(())
    }

    /// `/invoke`'s lifetime cap and replay cache apply to hooks requests.
    #[tokio::test]
    async fn replayed_or_overlong_invocations_are_refused() -> Result<()> {
        let fixture =
            hook_route_fixture(&[("hooks", "kv/documents", "tinycloud.hooks/subscribe")]).await?;
        let claim = [(fixture.hooks("kv/documents")?, SUBSCRIBE)];
        let header = fixture.session_header(&claim)?;
        let (first, _) = fixture
            .ticket(header.clone(), &fixture.space, "kv", "documents")
            .await;
        assert_eq!(first, Status::Ok);
        let (replayed, body) = fixture
            .ticket(header, &fixture.space, "kv", "documents")
            .await;
        assert_eq!(replayed, Status::Conflict, "{body}");

        let overlong = signed_header_expiring(
            &fixture.session.0,
            &fixture.session.1,
            vec![fixture.session_proof],
            &claim,
            Config::default().invocation.max_lifetime_secs as i64 + 600,
        )?;
        let (status, body) = fixture
            .ticket(overlong, &fixture.space, "kv", "documents")
            .await;
        assert_eq!(status, Status::Unauthorized, "{body}");
        Ok(())
    }

    /// Every refusal path leaves the database untouched: no invocation,
    /// replay, delegation, KV, or subscription rows.
    #[tokio::test]
    async fn refused_hooks_requests_write_nothing() -> Result<()> {
        let fixture = hook_route_fixture(&[
            ("hooks", "kv/documents", "tinycloud.hooks/subscribe"),
            ("hooks", "kv/documents", "tinycloud.hooks/list"),
        ])
        .await?;
        let before = fixture.persisted_rows().await?;
        let documents = fixture.hooks("kv/documents")?;
        let forged = |abilities: &'static [&'static str]| {
            fixture.forged_header(&[(documents.clone(), abilities)])
        };
        let undelegated = |abilities: &'static [&'static str]| {
            fixture.session_header(&[(fixture.hooks("kv").unwrap(), abilities)])
        };

        let statuses = [
            fixture
                .ticket(forged(SUBSCRIBE)?, &fixture.space, "kv", "documents")
                .await
                .0,
            fixture
                .ticket(undelegated(SUBSCRIBE)?, &fixture.space, "kv", "private")
                .await
                .0,
            fixture
                .register(forged(&["tinycloud.hooks/register"])?, &fixture.space)
                .await
                .0,
            fixture
                .register(
                    fixture
                        .session_header(&[(documents.clone(), &["tinycloud.hooks/register"])])?,
                    &fixture.space,
                )
                .await
                .0,
            fixture.list(forged(&["tinycloud.hooks/list"])?).await.0,
            fixture
                .list(undelegated(&["tinycloud.hooks/list"])?)
                .await
                .0,
            fixture
                .unregister(forged(&["tinycloud.hooks/unregister"])?, "sub_missing")
                .await
                .0,
            // Authorized caller, refused by the route's own scope check.
            fixture
                .unregister(
                    fixture.session_header(&[(documents.clone(), SUBSCRIBE)])?,
                    "sub_missing",
                )
                .await
                .0,
        ];
        assert!(
            statuses
                .iter()
                .all(|status| status.class().is_client_error()),
            "{statuses:?}"
        );
        assert_eq!(fixture.persisted_rows().await?, before);
        Ok(())
    }

    /// A ticket request refused after authorization (here a TTL that expires
    /// immediately) must not spend the invocation: the same header still
    /// mints a ticket once the request is valid.
    #[tokio::test]
    async fn refused_ticket_does_not_spend_the_invocation() -> Result<()> {
        let fixture =
            hook_route_fixture(&[("hooks", "kv/documents", "tinycloud.hooks/subscribe")]).await?;
        let header = fixture.session_header(&[(fixture.hooks("kv/documents")?, SUBSCRIBE)])?;
        let before = fixture.persisted_rows().await?;

        let (status, body) = fixture
            .ticket_with_ttl(header.clone(), &fixture.space, "kv", "documents", 0)
            .await;
        assert_eq!(status, Status::Unauthorized, "{body}");
        assert_eq!(fixture.persisted_rows().await?, before);

        let (status, body) = fixture
            .ticket(header, &fixture.space, "kv", "documents")
            .await;
        assert_eq!(status, Status::Ok, "{body}");
        Ok(())
    }
}
