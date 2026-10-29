use crate::{
    authorization::AuthHeaderGetter,
    config::Config,
    egress::{EgressPolicy, VettedDestination},
    hooks::{
        hook_scope_path, matches_scope, normalize_path_prefix_for_service, HookRuntime,
        HookSubscription, HookTicketClaims, HookTicketRequest, HookTicketResponse,
    },
    invocation_replay::InvocationReplayCache,
    policy_v3::PolicyV3Runtime,
    TinyCloud,
};
use rocket::{
    delete,
    form::FromForm,
    get,
    http::{Header, Status},
    post,
    response::{
        stream::{Event, EventStream},
        Responder,
    },
    serde::json::Json,
    State,
};
use serde::{Deserialize, Serialize};
use std::{future::Future, net::IpAddr, time::Duration, time::Instant};
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
    for space in admitted.invocation().0.spaces() {
        tinycloud_core::request_telemetry::observe_space(space);
    }
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
        subscription.path_prefix = normalize_path_prefix_for_service(
            &subscription.service,
            subscription.path_prefix.take(),
        );
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
        v: 2,
        sub: invocation.invoker.clone(),
        scopes: request.subscriptions,
        iat: now.unix_timestamp(),
        exp,
        parent_exp,
        authorizing_delegations: invocation.parents.clone(),
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

async fn hook_stream_deadline<F, Fut, Clock>(
    claims: &HookTicketClaims,
    max_ticket_ttl_seconds: u64,
    check_authority: F,
    mut now: Clock,
) -> Result<rocket::tokio::time::Instant, (Status, String)>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), (Status, String)>>,
    Clock: FnMut() -> OffsetDateTime,
{
    let initial_now = now();
    let deadline = claims
        .exp
        .min(claims.parent_exp)
        .min(initial_now.unix_timestamp() + max_ticket_ttl_seconds as i64);
    let expired = || (Status::Unauthorized, "hook ticket expired".to_string());
    if deadline <= initial_now.unix_timestamp() {
        return Err(expired());
    }
    let deadline_at = OffsetDateTime::from_unix_timestamp(deadline)
        .map_err(|error| (Status::InternalServerError, error.to_string()))?;

    check_authority().await?;

    let stream_now = now();
    if deadline_at <= stream_now {
        return Err(expired());
    }
    let remaining = deadline_at - stream_now;
    let remaining = Duration::new(
        remaining.whole_seconds() as u64,
        remaining.subsec_nanoseconds() as u32,
    );
    Ok(rocket::tokio::time::Instant::now() + remaining)
}

/// A hook SSE stream with headers that keep reverse proxies from holding it
/// back: nginx buffers proxied responses unless told `X-Accel-Buffering: no`,
/// which would delay every event until the stream closes (TC-720).
#[derive(Responder)]
pub struct HookEventStream<R> {
    stream: R,
    accel_buffering: Header<'static>,
    cache_control: Header<'static>,
}

impl<R> HookEventStream<R> {
    fn new(stream: R) -> Self {
        Self {
            stream,
            accel_buffering: Header::new("X-Accel-Buffering", "no"),
            cache_control: Header::new("Cache-Control", "no-cache"),
        }
    }
}

#[get("/hooks/events?<ticket>")]
pub async fn hook_events<'r>(
    ticket: &'r str,
    hooks: &'r State<HookRuntime>,
    tinycloud: &'r State<TinyCloud>,
) -> Result<HookEventStream<EventStream![Event + 'r]>, (Status, String)> {
    let claims = hooks
        .verify_ticket(ticket)
        .map_err(|e| (Status::Unauthorized, e))?;
    for scope in &claims.scopes {
        if let Ok(space) = scope.space.parse() {
            tinycloud_core::request_telemetry::observe_space(&space);
        }
    }
    let stream_deadline = hook_stream_deadline(
        &claims,
        hooks.config().max_ticket_ttl_seconds,
        || async {
            if tinycloud
                .delegation_chains_unrevoked(&claims.authorizing_delegations)
                .await
                .map_err(|error| (Status::InternalServerError, error.to_string()))?
            {
                Ok(())
            } else {
                Err((
                    Status::Unauthorized,
                    "hook ticket authority revoked".to_string(),
                ))
            }
        },
        OffsetDateTime::now_utc,
    )
    .await?;
    let lease = hooks
        .try_acquire_stream()
        .map_err(|e| (Status::TooManyRequests, e))?;

    let mut receiver = hooks.bus().subscribe();

    let stream = EventStream! {
        let _lease = lease;
        // `receiver` was subscribed only after ticket and authority checks above.
        if rocket::tokio::time::Instant::now() >= stream_deadline {
            return;
        }
        yield Event::json(&serde_json::json!({"type": "ready"})).event("ready");
        let deadline_sleep = rocket::tokio::time::sleep_until(stream_deadline);
        rocket::tokio::pin!(deadline_sleep);

        loop {
            rocket::tokio::select! {
                biased;
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
                            break;
                        }
                        Err(rocket::tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            }
        }
    }
    .heartbeat(Duration::from_secs(30));

    Ok(HookEventStream::new(stream))
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
    egress: &State<std::sync::Arc<EgressPolicy>>,
) -> Result<Json<HookWebhookResponse>, (Status, String)> {
    let invocation = authorize_hook_request(
        "server.hooks.webhook_register.auth",
        invocation.0,
        tinycloud,
        policy_v3,
        config,
    )
    .await?;
    let normalized = normalize_webhook_request(&request, egress)?;
    if !is_hook_action_authorized(&invocation, &normalized, "tinycloud.hooks/register") {
        return Err((
            Status::Forbidden,
            "webhook scope is not authorized".to_string(),
        ));
    }
    // Resolve the callback host only for an authorized caller.
    let (callback_url, _) = validate_webhook_callback_url(&request.callback_url, egress)
        .await
        .map_err(WebhookCallbackError::into_http_error)?;

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
    let normalized_prefix = normalize_path_prefix_for_service(&query.service, query.prefix.clone());
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

    // The database predicate is byte-exact and segment-aware. Keep this
    // authorization post-filter as defense in depth.
    let requested_path = hook_scope_path(&requested_scope.service, normalized_prefix.as_deref());
    rows.into_iter()
        .filter(|row| {
            row.space_id == requested_scope.space
                && row.target_service == requested_scope.service
                && scope_extends(
                    &hook_scope_path(&row.target_service, row.path_prefix.as_deref()),
                    &requested_path,
                )
                && (!matches!(requested_scope.service.as_str(), "sql" | "duckdb")
                    || tinycloud_core::write_hooks::database_scope_matches(
                        requested_scope.path_prefix.as_deref(),
                        row.path_prefix.as_deref(),
                    ))
        })
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
    let (requested_service, requested_path) = requested_scope
        .split_once('/')
        .map_or((requested_scope, None), |(service, path)| {
            (service, Some(path))
        });
    let (authorized_service, authorized_path) = authorized_scope
        .split_once('/')
        .map_or((authorized_scope, None), |(service, path)| {
            (service, Some(path))
        });
    if requested_service != authorized_service {
        return false;
    }
    if matches!(requested_service, "sql" | "duckdb") {
        return tinycloud_core::write_hooks::database_scope_matches(
            authorized_path,
            requested_path,
        );
    }
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
    policy: &EgressPolicy,
) -> Result<HookSubscription, (Status, String)> {
    let path_prefix =
        normalize_path_prefix_for_service(&request.service, request.path_prefix.clone());
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
    if request.secret.len() > 256 {
        return Err((Status::BadRequest, "secret exceeds 256 bytes".to_string()));
    }
    validate_callback_length(&request.callback_url)?;

    let url = reqwest::Url::parse(&request.callback_url)
        .map_err(|e| (Status::BadRequest, format!("invalid callbackUrl: {e}")))?;
    validate_callback_length(url.as_str())?;
    validate_webhook_shape(&url, policy)?;

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
    EgressPolicy::forbidden(ip).is_some()
}

fn validate_webhook_shape(
    url: &reqwest::Url,
    policy: &EgressPolicy,
) -> Result<(), (Status, String)> {
    #[cfg(test)]
    if policy.permits_test_http()
        && matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
    {
        return Ok(());
    }
    #[cfg(not(test))]
    let _ = policy;
    validate_webhook_url_shape(url)
}

/// Callback shape errors are terminal; temporary DNS/policy errors remain typed
/// so delivery can retry without permitting a forbidden connection.
#[derive(Debug, thiserror::Error)]
pub enum WebhookCallbackError {
    #[error("{0}")]
    Invalid(String),
    #[error("callbackUrl rejected: {0}")]
    Destination(#[from] crate::egress::EgressError),
}

impl WebhookCallbackError {
    /// Whether the callback may succeed once a temporary failure clears.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Destination(error) if error.is_retryable())
    }

    /// Preserve the registration endpoint's existing bad-callback status.
    pub fn into_http_error(self) -> (Status, String) {
        (Status::BadRequest, self.to_string())
    }
}

/// Validate a callback and resolve it once through the shared destination policy.
/// Callers must authorize registration before invoking this bounded DNS lookup.
pub async fn validate_webhook_callback_url(
    callback_url: &str,
    policy: &EgressPolicy,
) -> Result<(reqwest::Url, VettedDestination), WebhookCallbackError> {
    validate_callback_length(callback_url)
        .map_err(|(_, message)| WebhookCallbackError::Invalid(message))?;
    let url = reqwest::Url::parse(callback_url)
        .map_err(|e| WebhookCallbackError::Invalid(format!("invalid callbackUrl: {e}")))?;
    validate_callback_length(url.as_str())
        .map_err(|(_, message)| WebhookCallbackError::Invalid(message))?;
    validate_webhook_shape(&url, policy)
        .map_err(|(_, message)| WebhookCallbackError::Invalid(message))?;
    let destination = policy.resolve_url(&url).await?;
    #[cfg(test)]
    if url.scheme() == "http" && !destination.is_loopback() {
        return Err(WebhookCallbackError::Invalid(
            "test HTTP callback must resolve only to loopback".into(),
        ));
    }
    Ok((url, destination))
}

fn validate_callback_length(callback_url: &str) -> Result<(), (Status, String)> {
    if callback_url.len() > 2048 {
        return Err((
            Status::BadRequest,
            "callbackUrl exceeds 2048 bytes".to_string(),
        ));
    }
    Ok(())
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

    #[tokio::test]
    async fn hook_ticket_expiring_during_authority_lookup_is_rejected() {
        use std::sync::{
            atomic::{AtomicI64, Ordering},
            Arc,
        };

        let clock = Arc::new(AtomicI64::new(100));
        let authority_clock = Arc::clone(&clock);
        let request_clock = Arc::clone(&clock);
        let claims = HookTicketClaims {
            v: 2,
            sub: "did:key:subscriber".to_string(),
            scopes: Vec::new(),
            iat: 100,
            exp: 101,
            parent_exp: 101,
            authorizing_delegations: Vec::new(),
        };

        let result = hook_stream_deadline(
            &claims,
            300,
            move || async move {
                authority_clock.store(102, Ordering::Relaxed);
                Ok(())
            },
            move || {
                OffsetDateTime::from_unix_timestamp(request_clock.load(Ordering::Relaxed)).unwrap()
            },
        )
        .await;

        assert_eq!(
            result.unwrap_err(),
            (Status::Unauthorized, "hook ticket expired".to_string())
        );
    }

    #[tokio::test]
    async fn hook_event_stream_does_not_emit_queued_events_after_expiry() -> Result<()> {
        let hooks = test_hook_runtime();
        let (_tempdir, tinycloud) = test_tinycloud().await?;
        let client = rocket::local::asynchronous::Client::tracked(
            rocket::build()
                .mount("/", rocket::routes![hook_events])
                .manage(hooks.clone())
                .manage(tinycloud),
        )
        .await?;
        rocket::tokio::time::pause();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let ticket = hooks
            .sign_ticket(&HookTicketClaims {
                v: 2,
                sub: "did:key:subscriber".to_string(),
                scopes: vec![HookSubscription {
                    space: "tinycloud:space".to_string(),
                    service: "kv".to_string(),
                    path_prefix: None,
                    abilities: Vec::new(),
                }],
                iat: now,
                exp: now + 10,
                parent_exp: now + 10,
                authorizing_delegations: Vec::new(),
            })
            .map_err(anyhow::Error::msg)?;

        let mut responses = Vec::with_capacity(64);
        for _ in 0..64 {
            let response = client
                .get(format!("/hooks/events?ticket={ticket}"))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
            responses.push(response);
        }
        hooks.bus().publish(crate::hooks::WriteEvent {
            event_type: "write".to_string(),
            id: "epoch:1".to_string(),
            space: "tinycloud:space".to_string(),
            service: "kv".to_string(),
            ability: "tinycloud.kv/put".to_string(),
            path: Some("documents/1".to_string()),
            database_path: None,
            table_name: None,
            actor: "did:key:actor".to_string(),
            epoch: "epoch".to_string(),
            event_index: 1,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        });

        rocket::tokio::time::advance(Duration::from_secs(11)).await;
        for response in responses {
            assert!(
                response.into_string().await.unwrap_or_default().is_empty(),
                "queued events must not be emitted after the ticket deadline"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn hook_stream_emits_ready_before_queued_write_events() -> Result<()> {
        let hooks = test_hook_runtime();
        let (_tempdir, tinycloud) = test_tinycloud().await?;
        let client = rocket::local::asynchronous::Client::tracked(
            rocket::build()
                .mount("/", rocket::routes![hook_events])
                .manage(hooks.clone())
                .manage(tinycloud),
        )
        .await?;
        rocket::tokio::time::pause();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let ticket = hooks
            .sign_ticket(&HookTicketClaims {
                v: 2,
                sub: "did:key:subscriber".to_string(),
                scopes: vec![HookSubscription {
                    space: "tinycloud:space".to_string(),
                    service: "kv".to_string(),
                    path_prefix: None,
                    abilities: Vec::new(),
                }],
                iat: now,
                exp: now + 1,
                parent_exp: now + 1,
                authorizing_delegations: Vec::new(),
            })
            .map_err(anyhow::Error::msg)?;

        let response = client
            .get(format!("/hooks/events?ticket={ticket}"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        hooks.bus().publish(crate::hooks::WriteEvent {
            event_type: "write".to_string(),
            id: "epoch:1".to_string(),
            space: "tinycloud:space".to_string(),
            service: "kv".to_string(),
            ability: "tinycloud.kv/put".to_string(),
            path: Some("documents/1".to_string()),
            database_path: None,
            table_name: None,
            actor: "did:key:actor".to_string(),
            epoch: "epoch".to_string(),
            event_index: 1,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        });

        let body_future = response.into_string();
        rocket::tokio::pin!(body_future);
        let advance = async {
            rocket::tokio::task::yield_now().await;
            rocket::tokio::time::advance(Duration::from_secs(2)).await;
        };
        let (body, ()) = rocket::tokio::join!(&mut body_future, advance);
        let body = body.unwrap_or_default();

        let ready = body
            .find("event:ready\ndata:{\"type\":\"ready\"}\n\n")
            .expect("the authorized stream starts with a ready control event");
        let write = body
            .find("event:write\n")
            .expect("the prequeued write event is delivered");
        assert!(ready < write, "ready precedes write: {body}");

        let write_data = body[write..]
            .lines()
            .find_map(|line| line.strip_prefix("data:").map(str::trim_start))
            .expect("write event contains JSON data");
        let event: crate::hooks::WriteEvent = serde_json::from_str(write_data)?;
        assert_eq!(event.id, "epoch:1");
        assert_eq!(event.event_type, "write");
        Ok(())
    }

    #[tokio::test]
    async fn hook_stream_closes_when_broadcast_receiver_lags() -> Result<()> {
        let config = HooksConfig {
            sse_broadcast_capacity: 1,
            ..HooksConfig::default()
        };
        let hooks = HookRuntime::new(config, [7u8; 32]);
        let (_tempdir, tinycloud) = test_tinycloud().await?;
        let client = rocket::local::asynchronous::Client::tracked(
            rocket::build()
                .mount("/", rocket::routes![hook_events])
                .manage(hooks.clone())
                .manage(tinycloud),
        )
        .await?;
        rocket::tokio::time::pause();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let ticket = hooks
            .sign_ticket(&HookTicketClaims {
                v: 2,
                sub: "did:key:subscriber".to_string(),
                scopes: vec![HookSubscription {
                    space: "tinycloud:space".to_string(),
                    service: "kv".to_string(),
                    path_prefix: None,
                    abilities: Vec::new(),
                }],
                iat: now,
                exp: now + 1,
                parent_exp: now + 1,
                authorizing_delegations: Vec::new(),
            })
            .map_err(anyhow::Error::msg)?;

        let response = client
            .get(format!("/hooks/events?ticket={ticket}"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        for index in 1..=2 {
            hooks.bus().publish(crate::hooks::WriteEvent {
                event_type: "write".to_string(),
                id: format!("epoch:{index}"),
                space: "tinycloud:space".to_string(),
                service: "kv".to_string(),
                ability: "tinycloud.kv/put".to_string(),
                path: Some(format!("documents/{index}")),
                database_path: None,
                table_name: None,
                actor: "did:key:actor".to_string(),
                epoch: "epoch".to_string(),
                event_index: index,
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            });
        }

        let body_future = response.into_string();
        rocket::tokio::pin!(body_future);
        let advance = async {
            rocket::tokio::task::yield_now().await;
            rocket::tokio::time::advance(Duration::from_secs(2)).await;
        };
        let (body, ()) = rocket::tokio::join!(&mut body_future, advance);
        let body = body.unwrap_or_default();

        assert!(
            body.contains("event:ready\ndata:{\"type\":\"ready\"}\n\n"),
            "authorized stream emits readiness before closing: {body}"
        );
        assert!(
            !body.contains("event:write\n"),
            "a lagged stream closes rather than skipping missing writes: {body}"
        );
        Ok(())
    }

    async fn test_tinycloud() -> Result<(TempDir, TinyCloud)> {
        let tempdir = TempDir::new()?;
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string())).await?;
        let storage = NodeFileSystemConfig::new(tempdir.path()).open().await?;
        let tinycloud = TinyCloud::new(
            db.into(),
            Either::B(storage),
            StaticSecret::new(vec![0u8; 32]).unwrap(),
        )
        .await?;
        Ok((tempdir, tinycloud))
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

        let policy = EgressPolicy::from_config(&Config::default(), None).unwrap();
        let normalized =
            normalize_webhook_request(&request, &policy).expect("valid webhook request");
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
                normalize_webhook_request(
                    &request,
                    &EgressPolicy::from_config(&Config::default(), None).unwrap()
                )
                .is_err(),
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

    #[test]
    fn tc1132_callback_shape_rejects_embedded_private_and_allows_public_controls() {
        for address in [
            "::127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::a00:1",
            "2002:7f00:1::",
            "2001::1",
            "fec0::1",
        ] {
            let url = reqwest::Url::parse(&format!("https://[{address}]/hooks")).unwrap();
            assert_eq!(
                validate_webhook_url_shape(&url).unwrap_err().0,
                Status::BadRequest
            );
        }
        for address in ["192.2.1.1", "198.51.0.1", "1.1.1.1", "2606:4700::1111"] {
            assert!(!blocked_webhook_ip(address.parse().unwrap()), "{address}");
        }
    }

    #[tokio::test]
    async fn tc1132_registration_enforces_callback_and_secret_byte_limits() -> Result<()> {
        let fixture =
            hook_route_fixture(&[("hooks", "kv/documents", "tinycloud.hooks/register")]).await?;
        for (callback, secret) in [
            (
                format!("https://1.1.1.1/{}", "x".repeat(2049)),
                "secret".to_string(),
            ),
            ("https://1.1.1.1/hooks".to_string(), "é".repeat(129)),
            (
                format!("https://1.1.1.1/{}", "é".repeat(400)),
                "secret".to_string(),
            ),
        ] {
            let header = fixture.session_header(&[(
                fixture.hooks("kv/documents")?,
                &["tinycloud.hooks/register"],
            )])?;
            let response = fixture.client.post("/hooks/webhooks")
                .header(rocket::http::Header::new("Authorization", header))
                .header(rocket::http::ContentType::JSON)
                .body(serde_json::json!({
                    "space": fixture.space.to_string(), "service": "kv", "pathPrefix": "documents",
                    "callbackUrl": callback, "secret": secret,
                }).to_string()).dispatch().await;
            assert_eq!(response.status(), Status::BadRequest);
        }
        assert_eq!(fixture.persisted_rows().await?[4], 0);
        Ok(())
    }

    #[derive(Deserialize)]
    struct RegisteredWebhook {
        id: String,
    }

    async fn tc1132_register_url(
        fixture: &HookRouteFixture,
        callback: &str,
        secret: &str,
    ) -> Result<(Status, String)> {
        let header = fixture.session_header(&[(
            fixture.hooks("kv/documents")?,
            &["tinycloud.hooks/register"],
        )])?;
        let response = fixture
            .client
            .post("/hooks/webhooks")
            .header(rocket::http::Header::new("Authorization", header))
            .header(rocket::http::ContentType::JSON)
            .body(
                serde_json::json!({
                    "space": fixture.space.to_string(), "service": "kv", "pathPrefix": "documents",
                    "callbackUrl": callback, "secret": secret,
                })
                .to_string(),
            )
            .dispatch()
            .await;
        Ok((
            response.status(),
            response.into_string().await.unwrap_or_default(),
        ))
    }

    async fn tc1132_queue(fixture: &HookRouteFixture, subscription: &str, id: &str) -> Result<()> {
        use tinycloud_core::{models::hook_delivery, sea_orm::ActiveModelTrait};
        hook_delivery::ActiveModel::from(hook_delivery::Model {
            id: id.into(),
            subscription_id: subscription.into(),
            event_id: "event_egress".into(),
            payload_json: r#"{"id":"event_egress","key":"documents/note"}"#.into(),
            status: tinycloud_core::db::HOOK_DELIVERY_STATUS_PENDING.into(),
            attempts: 0,
            next_attempt_at: None,
            last_error: None,
            delivered_at: None,
            created_at: "2026-10-14T00:00:00Z".into(),
        })
        .insert(&fixture.db)
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn tc1132_registration_and_delivery_refuse_private_metadata_and_embedded_forms(
    ) -> Result<()> {
        use crate::egress::test_support::TestLookup;
        use tinycloud_core::models::hook_delivery;
        let lookup = std::sync::Arc::new(TestLookup::default());
        let policy = std::sync::Arc::new(EgressPolicy::for_test(vec![], lookup.clone(), false));
        let fixture = hook_route_fixture_with_policy(
            &[("hooks", "kv/documents", "tinycloud.hooks/register")],
            policy.clone(),
        )
        .await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let callbacks = [
            ("https://callback.test/hooks", Some("127.0.0.1")),
            ("https://callback.test/hooks", Some("10.0.0.1")),
            ("https://callback.test/hooks", Some("169.254.169.254")),
            ("https://callback.test/hooks", Some("::127.0.0.1")),
            ("https://callback.test/hooks", Some("64:ff9b::a9fe:a9fe")),
            ("https://callback.test/hooks", Some("2002:7f00:1::")),
            (
                "https://callback.test/hooks",
                Some("64:ff9b:1:808:8:808:7f00:0"),
            ),
            ("https://[::ffff:7f00:1]/hooks", None),
            ("https://[64:ff9b:1::a00:1]/hooks", None),
        ];
        for (index, (callback, answer)) in callbacks.iter().enumerate() {
            if let Some(answer) = answer {
                lookup.set("callback.test", &[answer]).await;
            }
            let (status, body) = tc1132_register_url(&fixture, callback, "secret").await?;
            assert_eq!(status, Status::BadRequest, "{callback}: {body}");
            let id = format!("sub_egress_{index}");
            fixture
                .tinycloud
                .create_hook_subscription(hook_subscription::Model {
                    id: id.clone(),
                    subscriber_did: did_of(&fixture.session.1).into(),
                    space_id: fixture.space.to_string(),
                    target_service: "kv".into(),
                    path_prefix: Some("documents".into()),
                    abilities_json: None,
                    callback_url: (*callback).into(),
                    encrypted_secret: ColumnEncryption::new([3; 32]).encrypt(b"secret"),
                    secret_key_id: "primary".into(),
                    active: true,
                    created_at: "2026-10-14T00:00:00Z".into(),
                })
                .await?;
            let delivery_id = format!("delivery_egress_{index}");
            tc1132_queue(&fixture, &id, &delivery_id).await?;
            crate::webhook_dispatcher::WebhookDispatcher::new(
                fixture.tinycloud.clone(),
                crate::config::HooksConfig::default(),
                ColumnEncryption::new([3; 32]),
                policy.clone(),
            )?
            .dispatch_due_once()
            .await?;
            let delivery = hook_delivery::Entity::find_by_id(delivery_id)
                .one(&fixture.db)
                .await?
                .unwrap();
            assert_eq!(
                delivery.status,
                tinycloud_core::db::HOOK_DELIVERY_STATUS_DEAD_LETTER
            );
            assert_eq!(delivery.attempts, 1);
            assert!(delivery
                .last_error
                .unwrap()
                .starts_with("callback URL rejected:"));
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn tc1132_rebinding_is_refused_after_successful_registration() -> Result<()> {
        use crate::egress::test_support::TestLookup;
        use tinycloud_core::models::hook_delivery;
        let lookup = std::sync::Arc::new(TestLookup::default());
        lookup
            .sequence("callback.test", &[&["1.1.1.1"], &["127.0.0.1"]])
            .await;
        let policy = std::sync::Arc::new(EgressPolicy::for_test(vec![], lookup.clone(), false));
        let fixture = hook_route_fixture_with_policy(
            &[("hooks", "kv/documents", "tinycloud.hooks/register")],
            policy.clone(),
        )
        .await?;
        let (status, body) =
            tc1132_register_url(&fixture, "https://callback.test/hooks", "secret").await?;
        assert_eq!(status, Status::Ok, "{body}");
        let subscription: RegisteredWebhook = serde_json::from_str(&body)?;
        tc1132_queue(&fixture, &subscription.id, "delivery_rebind").await?;
        crate::webhook_dispatcher::WebhookDispatcher::new(
            fixture.tinycloud.clone(),
            crate::config::HooksConfig::default(),
            ColumnEncryption::new([3; 32]),
            policy,
        )?
        .dispatch_due_once()
        .await?;
        let delivery = hook_delivery::Entity::find_by_id("delivery_rebind")
            .one(&fixture.db)
            .await?
            .unwrap();
        assert_eq!(
            delivery.status,
            tinycloud_core::db::HOOK_DELIVERY_STATUS_DEAD_LETTER
        );
        assert!(delivery
            .last_error
            .unwrap()
            .starts_with("callback URL rejected:"));
        assert_eq!(lookup.call_count(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn tc1132_registration_accepts_corrected_public_ranges_and_exact_byte_limits(
    ) -> Result<()> {
        for callback in [
            "https://192.2.1.1/hooks".to_string(),
            "https://198.51.0.1/hooks".to_string(),
            format!(
                "https://1.1.1.1/{}",
                "x".repeat(2048 - "https://1.1.1.1/".len())
            ),
        ] {
            let fixture =
                hook_route_fixture(&[("hooks", "kv/documents", "tinycloud.hooks/register")])
                    .await?;
            let secret = "é".repeat(128);
            let (status, body) = tc1132_register_url(&fixture, &callback, &secret).await?;
            assert_eq!(status, Status::Ok, "{body}");
            let subscription: RegisteredWebhook = serde_json::from_str(&body)?;
            let stored = fixture
                .tinycloud
                .find_hook_subscription(&subscription.id)
                .await?
                .unwrap();
            assert_eq!(stored.callback_url, callback);
            assert_eq!(
                ColumnEncryption::new([3; 32]).decrypt(&stored.encrypted_secret)?,
                secret.as_bytes()
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn tc1132_unauthorized_registration_never_resolves_callback() -> Result<()> {
        use crate::egress::test_support::TestLookup;
        let lookup = std::sync::Arc::new(TestLookup::default());
        let policy = std::sync::Arc::new(EgressPolicy::for_test(vec![], lookup.clone(), false));
        let fixture = hook_route_fixture_with_policy(
            &[("hooks", "kv/documents", "tinycloud.hooks/subscribe")],
            policy,
        )
        .await?;
        let (status, _) =
            tc1132_register_url(&fixture, "https://callback.test/hooks", "secret").await?;
        assert_eq!(status, Status::Unauthorized);
        assert_eq!(lookup.call_count(), 0);
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn tc1132_registered_delivery_uses_vetted_dns_without_proxy_and_preserves_hmac(
    ) -> Result<()> {
        use crate::{
            egress::test_support::{callback_server, TestLookup},
            test_support::{env_lock, EnvGuard},
        };
        use tinycloud_core::models::hook_delivery;
        #[allow(clippy::await_holding_lock)]
        let _lock = env_lock();
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let _proxy = EnvGuard::set("HTTPS_PROXY", format!("http://{}", proxy.local_addr()?));
        let _no_proxy = EnvGuard::set("NO_PROXY", "");
        let _no_proxy_lower = EnvGuard::set("no_proxy", "");
        let mut callback = callback_server(200, None).await?;
        let lookup = std::sync::Arc::new(TestLookup::default());
        lookup
            .set("callback.test", &["10.0.0.1", "127.0.0.1"])
            .await;
        let policy = std::sync::Arc::new(
            EgressPolicy::for_test(vec![], lookup.clone(), true)
                .with_test_root(callback.certificate.clone()),
        );
        let fixture = hook_route_fixture_with_policy(
            &[("hooks", "kv/documents", "tinycloud.hooks/register")],
            policy.clone(),
        )
        .await?;
        let (status, body) = tc1132_register_url(&fixture, &callback.url, "secret").await?;
        assert_eq!(status, Status::Ok, "{body}");
        let subscription: RegisteredWebhook = serde_json::from_str(&body)?;
        tc1132_queue(&fixture, &subscription.id, "delivery_tls").await?;
        crate::webhook_dispatcher::WebhookDispatcher::new(
            fixture.tinycloud.clone(),
            crate::config::HooksConfig::default(),
            ColumnEncryption::new([3; 32]),
            policy,
        )?
        .dispatch_due_once()
        .await?;
        let (body, headers) =
            tokio::time::timeout(Duration::from_secs(2), callback.requests.recv())
                .await?
                .unwrap();
        assert_eq!(body, br#"{"id":"event_egress","key":"documents/note"}"#);
        let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(b"secret")?;
        hmac::Mac::update(&mut mac, &body);
        let signature = format!(
            "sha256={}",
            hex::encode(hmac::Mac::finalize(mac).into_bytes())
        );
        assert_eq!(headers["X-TinyCloud-Signature"], signature);
        assert_eq!(headers["X-TinyCloud-Delivery-Id"], "delivery_tls");
        assert_eq!(headers["X-TinyCloud-Event-Id"], "event_egress");
        assert_eq!(headers["X-TinyCloud-Subscription-Id"], subscription.id);
        let delivery = hook_delivery::Entity::find_by_id("delivery_tls")
            .one(&fixture.db)
            .await?
            .unwrap();
        assert_eq!(
            delivery.status,
            tinycloud_core::db::HOOK_DELIVERY_STATUS_DELIVERED
        );
        assert_eq!(lookup.call_count(), 2, "registration once, delivery once");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), proxy.accept())
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn tc1132_healthy_refresh_preserves_authorized_delivery() -> Result<()> {
        use crate::egress::test_support::{callback_server, GatedLookup};
        use std::sync::{atomic::Ordering, Arc};
        use tinycloud_core::models::hook_delivery;
        let mut callback = callback_server(200, None).await?;
        let lookup = Arc::new(GatedLookup::default());
        lookup.answers.set("db.test", &["192.2.1.1"]).await;
        lookup.answers.set("callback.test", &["127.0.0.1"]).await;
        let policy = Arc::new(
            EgressPolicy::for_test(vec!["db.test".into()], lookup.clone(), true)
                .with_test_root(callback.certificate.clone()),
        );
        policy.refresh().await?;
        let fixture = hook_route_fixture_with_policy(
            &[("hooks", "kv/documents", "tinycloud.hooks/register")],
            policy.clone(),
        )
        .await?;
        let (status, body) = tc1132_register_url(&fixture, &callback.url, "refresh-secret").await?;
        assert_eq!(status, Status::Ok, "{body}");
        let subscription: RegisteredWebhook = serde_json::from_str(&body)?;
        tc1132_queue(&fixture, &subscription.id, "delivery_healthy_refresh").await?;
        lookup.paused.store(true, Ordering::SeqCst);
        let refresh = {
            let policy = policy.clone();
            tokio::spawn(async move { policy.refresh().await })
        };
        tokio::time::timeout(Duration::from_secs(1), lookup.started.notified()).await?;
        let dispatcher = crate::webhook_dispatcher::WebhookDispatcher::new(
            fixture.tinycloud.clone(),
            HooksConfig::default(),
            ColumnEncryption::new([3; 32]),
            policy.clone(),
        )?;
        let mut dispatch = tokio::spawn(async move { dispatcher.dispatch_due_once().await });
        let early = tokio::time::timeout(Duration::from_millis(100), &mut dispatch).await;
        let pending = hook_delivery::Entity::find_by_id("delivery_healthy_refresh")
            .one(&fixture.db)
            .await?
            .unwrap();
        lookup.paused.store(false, Ordering::SeqCst);
        lookup.release.add_permits(1);
        refresh.await??;
        if let Ok(result) = early {
            result??;
        } else {
            dispatch.await??;
        }
        assert_eq!(
            pending.status,
            tinycloud_core::db::HOOK_DELIVERY_STATUS_PENDING
        );
        assert_eq!(pending.attempts, 0);
        let (body, _) = tokio::time::timeout(Duration::from_secs(2), callback.requests.recv())
            .await?
            .unwrap();
        assert_eq!(body, br#"{"id":"event_egress","key":"documents/note"}"#);
        let delivered = hook_delivery::Entity::find_by_id("delivery_healthy_refresh")
            .one(&fixture.db)
            .await?
            .unwrap();
        assert_eq!(
            delivered.status,
            tinycloud_core::db::HOOK_DELIVERY_STATUS_DELIVERED
        );
        assert_eq!(delivered.attempts, 1);
        Ok(())
    }

    #[tokio::test]
    async fn tc1132_temporary_policy_failure_retries_and_recovers_with_original_payload(
    ) -> Result<()> {
        use crate::egress::test_support::{callback_server, TestLookup};
        use std::sync::Arc;
        use tinycloud_core::{
            models::hook_delivery,
            sea_orm::{ActiveModelTrait, ActiveValue::Set, IntoActiveModel},
        };
        let mut callback = callback_server(200, None).await?;
        let lookup = Arc::new(TestLookup::default());
        lookup.set("db.test", &["192.2.1.1"]).await;
        lookup.set("callback.test", &["127.0.0.1"]).await;
        let policy = Arc::new(
            EgressPolicy::for_test(vec!["db.test".into()], lookup.clone(), true)
                .with_test_root(callback.certificate.clone()),
        );
        policy.refresh().await?;
        let fixture = hook_route_fixture_with_policy(
            &[("hooks", "kv/documents", "tinycloud.hooks/register")],
            policy.clone(),
        )
        .await?;
        let (status, body) =
            tc1132_register_url(&fixture, &callback.url, "retry-policy-secret").await?;
        assert_eq!(status, Status::Ok, "{body}");
        let subscription: RegisteredWebhook = serde_json::from_str(&body)?;
        tc1132_queue(&fixture, &subscription.id, "delivery_policy_retry").await?;
        lookup.set("db.test", &[]).await;
        assert!(policy.refresh().await.is_err());
        let dispatcher = crate::webhook_dispatcher::WebhookDispatcher::new(
            fixture.tinycloud.clone(),
            HooksConfig::default(),
            ColumnEncryption::new([3; 32]),
            policy.clone(),
        )?;
        let before = OffsetDateTime::now_utc();
        dispatcher.dispatch_due_once().await?;
        let row = hook_delivery::Entity::find_by_id("delivery_policy_retry")
            .one(&fixture.db)
            .await?
            .unwrap();
        assert_eq!(
            row.status,
            tinycloud_core::db::HOOK_DELIVERY_STATUS_RETRYING
        );
        assert_eq!(row.attempts, 1);
        let next = OffsetDateTime::parse(row.next_attempt_at.as_deref().unwrap(), &Rfc3339)?;
        assert!((30..=32).contains(&(next - before).whole_seconds()));
        assert!(
            callback.requests.try_recv().is_err(),
            "failed policy must emit no request"
        );
        lookup.set("db.test", &["192.2.1.1"]).await;
        policy.refresh().await?;
        let mut due = row.into_active_model();
        due.next_attempt_at = Set(Some("2000-01-01T00:00:00Z".into()));
        due.update(&fixture.db).await?;
        dispatcher.dispatch_due_once().await?;
        let (body, headers) =
            tokio::time::timeout(Duration::from_secs(2), callback.requests.recv())
                .await?
                .unwrap();
        assert_eq!(body, br#"{"id":"event_egress","key":"documents/note"}"#);
        assert_eq!(headers["X-TinyCloud-Delivery-Id"], "delivery_policy_retry");
        let row = hook_delivery::Entity::find_by_id("delivery_policy_retry")
            .one(&fixture.db)
            .await?
            .unwrap();
        assert_eq!(
            row.status,
            tinycloud_core::db::HOOK_DELIVERY_STATUS_DELIVERED
        );
        assert_eq!(row.attempts, 2);
        Ok(())
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
        let (_tempdir, tinycloud) = test_tinycloud().await?;
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
        let (_tempdir, tinycloud) = test_tinycloud().await?;
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
        let (_tempdir, tinycloud) = test_tinycloud().await?;
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

    #[test]
    fn sql_hook_grants_match_exact_databases_or_slash_namespaces() {
        assert!(scope_extends("sql/appA/connectors", "sql/appA/connectors"));
        assert!(!scope_extends(
            "sql/appA/connectors/private",
            "sql/appA/connectors"
        ));
        assert!(scope_extends(
            "sql/appA/connectors/private",
            "sql/appA/connectors/"
        ));
        assert_eq!(
            normalize_path_prefix_for_service("sql", Some("/appA/connectors/".into())).as_deref(),
            Some("appA/connectors/")
        );
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
        _tempdir: TempDir,
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
        hook_route_fixture_with_policy(
            grants,
            std::sync::Arc::new(EgressPolicy::from_config(&Config::default(), None)?),
        )
        .await
    }

    async fn hook_route_fixture_with_policy(
        grants: &[(&str, &str, &str)],
        policy: std::sync::Arc<EgressPolicy>,
    ) -> Result<HookRouteFixture> {
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
        for id in [&space, &other_space] {
            storage.create(id).await?;
        }
        let tinycloud = TinyCloud::new(
            db.clone().into(),
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
                    hook_events,
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
            .manage(policy)
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
            _tempdir: tempdir,
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
            self.list_prefix(header, "documents").await
        }

        async fn list_prefix(&self, header: String, prefix: &str) -> (Status, String) {
            let response = self
                .client
                .get(format!(
                    "/hooks/webhooks?space={}&service=kv&prefix={prefix}",
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
            v: 2,
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
            authorizing_delegations: Vec::new(),
        };
        let stale = pre_fix.sign_ticket(&claims).unwrap();
        assert!(current
            .verify_ticket(&current.sign_ticket(&claims).unwrap())
            .is_ok());

        let (_tempdir, tinycloud) = test_tinycloud().await?;
        let client = rocket::local::asynchronous::Client::tracked(
            rocket::build()
                .mount("/", rocket::routes![hook_events])
                .manage(current)
                .manage(tinycloud),
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

    #[tokio::test]
    async fn hook_stream_rejects_ticket_after_authority_revocation() -> Result<()> {
        use tinycloud_core::{
            models::revocation,
            sea_orm::{ActiveModelTrait, ActiveValue::Set},
        };

        let fixture =
            hook_route_fixture(&[("hooks", "kv/documents", "tinycloud.hooks/subscribe")]).await?;
        let claim = [(fixture.hooks("kv/documents")?, SUBSCRIBE)];

        let (status, live_body) = fixture
            .ticket(
                fixture.session_header(&claim)?,
                &fixture.space,
                "kv",
                "documents",
            )
            .await;
        assert_eq!(status, Status::Ok, "{live_body}");
        let live_ticket: serde_json::Value = serde_json::from_str(&live_body)?;
        let live_response = fixture
            .client
            .get(format!(
                "/hooks/events?ticket={}",
                live_ticket["ticket"].as_str().expect("signed ticket")
            ))
            .dispatch()
            .await;
        assert_eq!(live_response.status(), Status::Ok);

        let (status, revoked_body) = fixture
            .ticket(
                fixture.session_header(&claim)?,
                &fixture.space,
                "kv",
                "documents",
            )
            .await;
        assert_eq!(status, Status::Ok, "{revoked_body}");
        let revoked_ticket: serde_json::Value = serde_json::from_str(&revoked_body)?;
        revocation::ActiveModel {
            id: Set(tinycloud_core::hash::hash(b"revoke-hooks-stream")),
            revoker: Set(did_of(&fixture.owner.1).to_string()),
            revoked: Set(Hash::from(fixture.session_proof)),
            serialization: Set(b"revoke-hooks-stream".to_vec()),
            revoked_at: Set(Some(OffsetDateTime::now_utc())),
        }
        .insert(&fixture.db)
        .await?;
        let response = fixture
            .client
            .get(format!(
                "/hooks/events?ticket={}",
                revoked_ticket["ticket"].as_str().expect("signed ticket")
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized);
        assert_eq!(
            response.into_string().await.as_deref(),
            Some("hook ticket authority revoked")
        );
        Ok(())
    }

    #[tokio::test]
    async fn hook_stream_disables_proxy_buffering() -> Result<()> {
        let fixture =
            hook_route_fixture(&[("hooks", "kv/documents", "tinycloud.hooks/subscribe")]).await?;
        let claim = [(fixture.hooks("kv/documents")?, SUBSCRIBE)];
        let (status, body) = fixture
            .ticket(
                fixture.session_header(&claim)?,
                &fixture.space,
                "kv",
                "documents",
            )
            .await;
        assert_eq!(status, Status::Ok, "{body}");
        let ticket: serde_json::Value = serde_json::from_str(&body)?;
        let response = fixture
            .client
            .get(format!(
                "/hooks/events?ticket={}",
                ticket["ticket"].as_str().expect("signed ticket")
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.content_type(),
            Some(rocket::http::ContentType::EventStream)
        );
        let headers = response.headers();
        assert_eq!(headers.get("X-Accel-Buffering").collect::<Vec<_>>(), ["no"]);
        assert_eq!(
            headers.get("Cache-Control").collect::<Vec<_>>(),
            ["no-cache"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn hook_stream_rejects_revoked_shared_ancestor_at_traversal_boundary() -> Result<()> {
        use tinycloud_core::{
            models::revocation,
            relationships::parent_delegations,
            sea_orm::{ActiveModelTrait, ActiveValue::Set},
        };

        let fixture = hook_route_fixture(&[]).await?;
        let mut ids: Vec<_> = (0..tinycloud_core::models::revocation::MAX_CHAIN_TRAVERSAL_NODES)
            .map(|index| {
                tinycloud_core::hash::hash(
                    format!("hook-shared-ancestor-boundary-{index}").as_bytes(),
                )
            })
            .collect();
        ids.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
        let (roots, hidden_ancestor) =
            ids.split_at(tinycloud_core::models::revocation::MAX_CHAIN_TRAVERSAL_NODES - 1);
        for id in &ids {
            delegation::ActiveModel {
                id: Set(*id),
                delegator: Set(did_of(&fixture.owner.1).to_string()),
                delegatee: Set(did_of(&fixture.session.1).to_string()),
                expiry: Set(None),
                issued_at: Set(None),
                not_before: Set(None),
                facts: Set(None),
                serialization: Set(id.as_ref().to_vec()),
            }
            .insert(&fixture.db)
            .await?;
        }
        for parent in [
            roots[tinycloud_core::models::revocation::MAX_CHAIN_TRAVERSAL_NODES - 3],
            roots[tinycloud_core::models::revocation::MAX_CHAIN_TRAVERSAL_NODES - 2],
            hidden_ancestor[0],
        ] {
            parent_delegations::ActiveModel {
                child: Set(roots[0]),
                parent: Set(parent),
            }
            .insert(&fixture.db)
            .await?;
        }
        revocation::ActiveModel {
            id: Set(tinycloud_core::hash::hash(b"revoke-hidden-stream-ancestor")),
            revoker: Set(did_of(&fixture.owner.1).to_string()),
            revoked: Set(hidden_ancestor[0]),
            serialization: Set(b"revoke-hidden-stream-ancestor".to_vec()),
            revoked_at: Set(Some(OffsetDateTime::now_utc())),
        }
        .insert(&fixture.db)
        .await?;

        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = HookTicketClaims {
            v: 2,
            sub: "did:key:subscriber".to_string(),
            scopes: vec![HookSubscription {
                space: fixture.space.to_string(),
                service: "kv".to_string(),
                path_prefix: Some("documents".to_string()),
                abilities: Vec::new(),
            }],
            iat: now,
            exp: now + 60,
            parent_exp: now + 60,
            authorizing_delegations: roots.iter().map(|id| id.to_cid(0x55)).collect(),
        };
        let ticket = test_hook_runtime()
            .sign_ticket(&claims)
            .map_err(anyhow::Error::msg)?;
        let response = fixture
            .client
            .get(format!("/hooks/events?ticket={ticket}"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized);
        assert_eq!(
            response.into_string().await.as_deref(),
            Some("hook ticket authority revoked")
        );
        Ok(())
    }

    #[tokio::test]
    async fn expired_hook_ticket_skips_delegation_revocation_lookup() -> Result<()> {
        let fixture = hook_route_fixture(&[]).await?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let authorizing_delegations = (0
            ..=tinycloud_core::models::revocation::MAX_CHAIN_TRAVERSAL_NODES)
            .map(|index| {
                tinycloud_core::hash::hash(format!("expired-ticket-root-{index}").as_bytes())
                    .to_cid(0x55)
            })
            .collect();
        let ticket = test_hook_runtime()
            .sign_ticket(&HookTicketClaims {
                v: 2,
                sub: "did:key:subscriber".to_string(),
                scopes: vec![HookSubscription {
                    space: fixture.space.to_string(),
                    service: "kv".to_string(),
                    path_prefix: Some("documents".to_string()),
                    abilities: Vec::new(),
                }],
                iat: now - 120,
                exp: now - 60,
                parent_exp: now - 60,
                authorizing_delegations,
            })
            .map_err(anyhow::Error::msg)?;

        let response = fixture
            .client
            .get(format!("/hooks/events?ticket={ticket}"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized);
        assert_eq!(
            response.into_string().await.as_deref(),
            Some("hook ticket expired")
        );
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

    /// The subscription query's `LIKE 'prefix/%'` treats `_` and `%` as
    /// wildcards and, on SQLite, ignores ASCII case. Listing must return only
    /// rows inside the authorized scope, never another subscriber's rows that
    /// merely match the pattern.
    #[tokio::test]
    async fn list_returns_only_rows_inside_the_authorized_scope() -> Result<()> {
        let fixture =
            hook_route_fixture(&[("hooks", "kv/my_docs", "tinycloud.hooks/list")]).await?;
        let space = fixture.space.to_string();
        let row = |id: &str, path_prefix: &str| hook_subscription::Model {
            id: id.to_string(),
            subscriber_did: "did:key:other-subscriber".to_string(),
            space_id: space.clone(),
            target_service: "kv".to_string(),
            path_prefix: Some(path_prefix.to_string()),
            abilities_json: None,
            callback_url: format!("https://1.1.1.1/{id}"),
            encrypted_secret: vec![1, 2, 3],
            secret_key_id: HOOK_WEBHOOK_SECRET_KEY_ID.to_string(),
            active: true,
            created_at: "2026-10-05T00:00:00Z".to_string(),
        };
        hook_subscription::Entity::insert_many(
            [
                row("exact", "my_docs"),
                row("nested", "my_docs/inbox"),
                row("upper", "MY_DOCS/secret"),
                row("underscore", "myXdocs/secret"),
                row("percent", "my%docs/secret"),
                row("sibling", "my_docs_archive/secret"),
            ]
            .map(hook_subscription::ActiveModel::from),
        )
        .exec(&fixture.db)
        .await?;

        let header =
            fixture.session_header(&[(fixture.hooks("kv/my_docs")?, &["tinycloud.hooks/list"])])?;
        let (status, body) = fixture.list_prefix(header, "my_docs").await;
        assert_eq!(status, Status::Ok, "{body}");
        let listed: Vec<serde_json::Value> = serde_json::from_str(&body)?;
        let mut ids = listed
            .iter()
            .map(|row| row["id"].as_str().expect("webhook id"))
            .collect::<Vec<_>>();
        ids.sort_unstable();
        assert_eq!(ids, ["exact", "nested"]);
        Ok(())
    }
}
